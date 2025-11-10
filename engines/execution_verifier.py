"""
Execution verification using Playwright
Only used for URLs that showed reflection - minimizes overhead
"""

import asyncio
from typing import Dict, Optional
from pathlib import Path
from datetime import datetime

from playwright.async_api import async_playwright, Browser, BrowserContext


class ExecutionVerifier:
    def __init__(
        self, 
        concurrency: int = 3, 
        timeout: int = 15,
        screenshots: bool = False
    ):
        self.concurrency = concurrency
        self.timeout = timeout * 1000  # Convert to milliseconds
        self.screenshots = screenshots
        
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context_semaphore = asyncio.Semaphore(concurrency)
        
        # Setup screenshots directory
        if screenshots:
            self.screenshot_dir = Path('xss_screenshots')
            self.screenshot_dir.mkdir(exist_ok=True)
    
    async def initialize(self):
        """Initialize Playwright browser (lazy init)"""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox'
            ]
        )
    
    async def close(self):
        """Clean up browser resources"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def verify_execution(self, url_data: Dict) -> Dict:
        """Verify if XSS actually executes JavaScript"""
        async with self.context_semaphore:
            return await self._verify_in_context(url_data)
    
    async def _verify_in_context(self, url_data: Dict) -> Dict:
        """Verify execution using a browser context"""
        result = {
            'executed': False,
            'evidence': [],
            'screenshot': None
        }
        
        # Create isolated context (faster than new browser)
        context: BrowserContext = await self.browser.new_context(
            viewport={'width': 1280, 'height': 720},
            ignore_https_errors=True
        )
        
        try:
            page = await context.new_page()
            
            # Setup execution detection
            execution_detected = {'value': False, 'method': None}
            
            # Override alert/confirm/prompt
            page.on('dialog', lambda dialog: self._handle_dialog(dialog, execution_detected))
            
            # Monitor console for XSS indicators
            console_logs = []
            page.on('console', lambda msg: console_logs.append(msg.text))
            
            # Inject detection script before navigation
            await page.add_init_script("""
                // Override common XSS sinks
                window.xssDetected = false;
                
                const originalAlert = window.alert;
                window.alert = function() {
                    window.xssDetected = true;
                    window.xssMethod = 'alert';
                    originalAlert.apply(this, arguments);
                };
                
                const originalConfirm = window.confirm;
                window.confirm = function() {
                    window.xssDetected = true;
                    window.xssMethod = 'confirm';
                    return originalConfirm.apply(this, arguments);
                };
                
                const originalPrompt = window.prompt;
                window.prompt = function() {
                    window.xssDetected = true;
                    window.xssMethod = 'prompt';
                    return originalPrompt.apply(this, arguments);
                };
                
                // Detect document.write
                const originalWrite = document.write;
                document.write = function(content) {
                    if (content && content.includes('script')) {
                        window.xssDetected = true;
                        window.xssMethod = 'document.write';
                    }
                    return originalWrite.apply(this, arguments);
                };
            """)
            
            # Navigate to URL
            try:
                await page.goto(
                    url_data['url'], 
                    timeout=self.timeout,
                    wait_until='domcontentloaded'
                )
                
                # Wait a bit for JS execution
                await page.wait_for_timeout(2000)
                
            except Exception as e:
                # Page might crash due to XSS - this is actually good!
                if 'net::ERR_BLOCKED_BY_RESPONSE' not in str(e):
                    result['evidence'].append({
                        'type': 'page_error',
                        'details': f'Page navigation error: {str(e)}'
                    })
            
            # Check if XSS was detected
            try:
                xss_detected = await page.evaluate('window.xssDetected || false')
                xss_method = await page.evaluate('window.xssMethod || null')
                
                if xss_detected:
                    result['executed'] = True
                    result['evidence'].append({
                        'type': 'javascript_execution',
                        'method': xss_method,
                        'details': f'XSS executed via {xss_method}'
                    })
            except:
                pass  # Page might be unresponsive after XSS
            
            # Check for dialog that was triggered
            if execution_detected['value']:
                result['executed'] = True
                result['evidence'].append({
                    'type': 'dialog_triggered',
                    'method': execution_detected['method'],
                    'details': f"{execution_detected['method']} dialog was triggered"
                })
            
            # Check console logs for XSS indicators
            xss_console_patterns = ['xss', 'script', 'injection', 'alert(', 'confirm(']
            for log in console_logs:
                if any(pattern in log.lower() for pattern in xss_console_patterns):
                    result['executed'] = True
                    result['evidence'].append({
                        'type': 'console_log',
                        'details': f'Console: {log[:100]}'
                    })
                    break
            
            # Check for script execution in DOM
            try:
                script_elements = await page.query_selector_all('script')
                for script in script_elements:
                    content = await script.inner_text()
                    if url_data['payload'] in content:
                        result['executed'] = True
                        result['evidence'].append({
                            'type': 'dom_injection',
                            'details': 'Payload injected into script tag'
                        })
                        break
            except:
                pass
            
            # Take screenshot if XSS was verified
            if result['executed'] and self.screenshots:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                screenshot_path = self.screenshot_dir / f"xss_{timestamp}.png"
                await page.screenshot(path=str(screenshot_path))
                result['screenshot'] = str(screenshot_path)
            
        except Exception as e:
            # Some errors might indicate successful XSS (e.g., page crash)
            if 'navigation' in str(e).lower() or 'timeout' in str(e).lower():
                # Not necessarily an XSS
                pass
            else:
                result['evidence'].append({
                    'type': 'error',
                    'details': str(e)
                })
        
        finally:
            await context.close()
        
        return result
    
    @staticmethod
    def _handle_dialog(dialog, execution_detected: Dict):
        """Handle JavaScript dialogs (alert/confirm/prompt)"""
        execution_detected['value'] = True
        execution_detected['method'] = dialog.type
        
        # Auto-dismiss dialog
        asyncio.create_task(dialog.dismiss())