import Foundation

protocol OTParserConfig {
    var knownServices: [String] { get }
    var authWords: Set<String> { get }
    var servicePatterns: [String] { get }
}

struct OTPParserConstants {
    static let googleOTPRegex = try! NSRegularExpression(pattern: #"\b(G-[A-Z0-9]{5})\b"#)

    static let endingCharacters: Set<Character> = [" ", ".", ",", ";", "!", "?", "\n", "\r"]
    
    static let knownServices = [
        "td ameritrade",
        "coinbase",
        "ally",
        "schwab",
        "id.me",
        "bofa",
        "dropboxing",
        "wise.com",
        "paypal",
        "venmo",
        "cash",
        "segment",
        "verizon",
        "kotak bank",
        "weibo",
        "wechat",
        "whatsapp",
        "viber",
        "snapchat",
        "line",
        "slack",
        "signal",
        "telegram",
        "allo",
        "kakaotalk",
        "voxer",
        "im+",
        "skype",
        "facebook",
        "microsoft",
        "google",
        "twitter",
        "instagram",
        "sony",
        "apple",
        "ubereats",
        "uber",
        "lyft",
        "postmates",
        "doordash",
        "delivery.com",
        "eat24",
        "foodler",
        "amazon",
        "tencent",
        "alibaba",
        "taobao",
        "baidu",
        "youku",
        "toutaio",
        "netease",
        "yandex",
        "uc browser",
        "qq browser",
        "qmenu",
        "sogou",
        "bbm",
        "ebay",
        "intel",
        "cisco",
        "citizen",
        "oracle",
        "xerox",
        "ibm",
        "foursquare",
        "hotmail",
        "outlook",
        "yahoo",
        "netflix",
        "spotify",
        "producthunt",
        "nike",
        "adidas",
        "shopify",
        "wordpress",
        "yelp eats",
        "yelp",
        "drizly",
        "eaze",
        "gopuff",
        "grubhub",
        "seamless",
        "foodpanda",
        "freshdirect",
        "github",
        "flickr",
        "etsy",
        "bank of america",
        "lenscrafters",
        "zocdoc",
        "flycleaners",
        "cleanly",
        "handy",
        "twilio",
        "kik",
        "xbox",
        "imo",
        "kayak",
        "grab",
        "qq",
        "moonpay",
        "robinhood",
        "ao retail",
        "cater allen",
        "apple pay",
        "bill.com",
        "amex",
        "sia",
        "fanduel",
        "cart"
      ]
    
    static let authWords: Set<String> = [
        "your",
        "auth",
        "login",
        "activation",
        "authentication",
        "verification",
        "confirmation",
        "access code",
        "code",
        "pin",
        "otp",
        "purchase",
        "receipt",
        "phone",
        "number",
        "security",
        "2-step",
        "2-fac",
        "2-factor"
      ]
    
    public static let servicePatterns = [
        #"\bfor\s+your\s+([\w\d ]{4,64})\s+account\b"#,
        #"\bon\s+your\s+([\w\d ]{4,64})\s+account\b"#,
        #"\bas\s+your\s+([\w\d ]{4,64})\s+account\b"#,
        #"\bas\s+([\w\d ]{4,64})\s+account\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+account\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+verification\s+code\b"#,

        #"\byour\s+([\w\d ]{4,64})\s+verification\s+number\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+verification\s+pin\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+activation\s+code\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+activation\s+number\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+activation\s+pin\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+otp\s+code\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+otp\s+pin\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+auth\s+pin\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+auth\s+code\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+authentication\s+code\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+authentication\s+number\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+authentication\s+pin\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+security\s+code\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+security\s+number\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+security\s+pin\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+confirmation\s+code\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+confirmation\s+number\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+confirmation\s+pin\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+access\s+code\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+access\s+number\b"#,
        #"\byour\s+([\w\d ]{4,64})\s+access\s+pin\b"#,

        #"\byour\s+verification\s+code\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+verification\s+number\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+verification\s+pin\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+activation\s+code\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+activation\s+number\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+activation\s+pin\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+otp\s+code\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+otp\s+pin\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+auth\s+code\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+auth\s+pin\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+authentication\s+code\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+authentication\s+number\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+authentication\s+pin\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+security\s+code\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+security\s+number\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+security\s+pin\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+confirmation\s+code\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+confirmation\s+number\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+confirmation\s+pin\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+access\s+code\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+access\s+number\s+for\s+([\w\d ]{4,64})\b"#,
        #"\byour\s+access\s+pin\s+for\s+([\w\d ]{4,64})\b"#,

        #"\byour\s+([\w\d]{4,64})\s+code\b"#,
        #"\byour\s+([\w\d]{4,64})\s+pin\b"#,

        #"\b([\w\d]{4,64})\s+login\s+verification\s+code\b"#,
        #"\b([\w\d]{4,64})\s+login\s+verification\s+number\b"#,
        #"\b([\w\d]{4,64})\s+login\s+verification\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+login\s+activation\s+code\b"#,
        #"\b([\w\d]{4,64})\s+login\s+activation\s+number\b"#,
        #"\b([\w\d]{4,64})\s+login\s+activation\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+login\s+otp\s+code\b"#,
        #"\b([\w\d]{4,64})\s+login\s+otp\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+login\s+auth\s+code\b"#,
        #"\b([\w\d]{4,64})\s+login\s+auth\s+number\b"#,
        #"\b([\w\d]{4,64})\s+login\s+auth\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+login\s+authentication\s+code\b"#,
        #"\b([\w\d]{4,64})\s+login\s+authentication\s+number\b"#,
        #"\b([\w\d]{4,64})\s+login\s+authentication\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+login\s+security\s+code\b"#,
        #"\b([\w\d]{4,64})\s+login\s+security\s+number\b"#,
        #"\b([\w\d]{4,64})\s+login\s+security\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+login\s+confirmation\s+code\b"#,
        #"\b([\w\d]{4,64})\s+login\s+confirmation\s+number\b"#,
        #"\b([\w\d]{4,64})\s+login\s+confirmation\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+login\s+access\s+code\b"#,
        #"\b([\w\d]{4,64})\s+login\s+access\s+number\b"#,
        #"\b([\w\d]{4,64})\s+login\s+access\s+pin\b"#,

        #"\b([\w\d]{4,64})\s+verification\s+code\b"#,
        #"\b([\w\d]{4,64})\s+verification\s+number\b"#,
        #"\b([\w\d]{4,64})\s+verification\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+activation\s+code\b"#,
        #"\b([\w\d]{4,64})\s+activation\s+number\b"#,
        #"\b([\w\d]{4,64})\s+activation\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+otp\s+code\b"#,
        #"\b([\w\d]{4,64})\s+otp\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+auth\s+code\b"#,
        #"\b([\w\d]{4,64})\s+auth\s+number\b"#,
        #"\b([\w\d]{4,64})\s+auth\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+authentication\s+code\b"#,
        #"\b([\w\d]{4,64})\s+authentication\s+number\b"#,
        #"\b([\w\d]{4,64})\s+authentication\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+security\s+code\b"#,
        #"\b([\w\d]{4,64})\s+security\s+number\b"#,
        #"\b([\w\d]{4,64})\s+security\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+confirmation\s+code\b"#,
        #"\b([\w\d]{4,64})\s+confirmation\s+number\b"#,
        #"\b([\w\d]{4,64})\s+confirmation\s+pin\b"#,
        #"\b([\w\d]{4,64})\s+access\s+code\b"#,
        #"\b([\w\d]{4,64})\s+access\s+number\b"#,
        #"\b([\w\d]{4,64})\s+access\s+pin\b"#,

        #"^welcome\s+to\s+([\w\d ]{4,64})[,;.]"#,
        #"^welcome\s+to\s+([\w\d]{4,64})\b"#,

        #"^\[([^\]\d]{4,64})]"#,
        #"^\(([^)\d]{4,64})\)"#,

        #"\bcode\s+for\s+([\w\d]{3,64})\b"#,
        #"\bpin\s+for\s+([\w\d]{3,64})\b"#,
        #"\botp\s+for\s+([\w\d]{3,64})\b"#,
        #"\bnumber\s+for\s+([\w\d]{3,64})\b"#,

        #"\b([\w\d]{3,64})\s+login\s+code\b"#,
        #"\b([\w\d]{3,64})\s+login\s+number\b"#,
        #"\b([\w\d]{3,64})\s+login\s+pin\b"#,

        #"\b([\w\d]{3,64})\s+code\b"#,
        #"\b([\w\d]{3,64})\s+number\b"#,
        #"\b([\w\d]{3,64})\s+pin\b"#,

        #"【([\u4e00-\u9fa5\d\w]+)"#,
    ].map { regExp in try! NSRegularExpression(pattern: regExp) }
    
    enum CodeMatchingRegularExpressions: CaseIterable {
        case standardFourToEight
        case dashedThreeAndThree
        case alphanumericWordContainingDigits
        case customIgnoreDotZeroZero

        var regex: NSRegularExpression {
            switch self {
            case .standardFourToEight:
                return try! NSRegularExpression(pattern: #"\b(\d{4,8})\b"#)
            case .dashedThreeAndThree:
                return try! NSRegularExpression(pattern: #"\b(\d{3}[- ]\d{3})\b"#)
            case .alphanumericWordContainingDigits:
                return try! NSRegularExpression(pattern: #"\b([a-zA-Z]*\d[a-zA-Z\d]{3,})\b"#, options: .caseInsensitive)
            case .customIgnoreDotZeroZero:
                return try! NSRegularExpression(pattern: #"\b(\d{4,8}(?:\.00)?)\b"#)
            }
        }

        static var allPatterns: [NSRegularExpression] {
            return allCases.map { $0.regex }
        }
    }
}
