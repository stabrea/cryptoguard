"""
Secure Password Generation Module

Generates cryptographically random passwords and passphrases.
Uses secrets module (CSPRNG) for all random choices.
"""

import secrets
import string
from dataclasses import dataclass


# Diceware-style word list (curated subset for demonstration).
# A real deployment should use the full EFF large wordlist:
# https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
_WORDLIST: list[str] = [
    "abandon", "ability", "absent", "absorb", "abstract", "academy",
    "accept", "achieve", "acquire", "adapt", "address", "adjust",
    "admit", "advance", "advice", "afford", "agenda", "agree",
    "airport", "alarm", "album", "alert", "alien", "allow",
    "almost", "alpha", "already", "alter", "amazing", "among",
    "amount", "anchor", "ancient", "anger", "angle", "animal",
    "annual", "answer", "anxiety", "apart", "apology", "appeal",
    "apple", "approve", "arctic", "arena", "argue", "armor",
    "army", "arrive", "arrow", "artist", "assume", "athlete",
    "atlas", "atom", "auction", "audit", "august", "autumn",
    "average", "avocado", "avoid", "awake", "awesome", "badge",
    "balance", "bamboo", "banana", "banner", "barely", "barrel",
    "basket", "battle", "beach", "beacon", "beauty", "become",
    "benefit", "beyond", "bicycle", "blanket", "blossom", "board",
    "bonus", "border", "bounce", "bracket", "brave", "breeze",
    "bridge", "bright", "broken", "bronze", "bubble", "budget",
    "buffalo", "bundle", "burden", "burger", "butter", "cabin",
    "cactus", "camera", "campus", "canal", "candle", "canyon",
    "capture", "carbon", "cargo", "carpet", "casino", "castle",
    "catalog", "caught", "caution", "cave", "cedar", "celery",
    "cement", "census", "center", "cereal", "certain", "chair",
    "chalk", "chamber", "change", "chapter", "charge", "charm",
    "cherry", "chicken", "chief", "chimney", "choice", "chrome",
    "chunk", "circle", "citizen", "claim", "clap", "clarify",
    "classic", "clean", "clever", "climate", "clinic", "clock",
    "cloud", "cluster", "coach", "coconut", "coffee", "collect",
    "color", "column", "combine", "comfort", "comic", "common",
    "company", "concert", "conduct", "confirm", "congress", "connect",
    "consider", "control", "convert", "cookie", "copper", "coral",
    "corner", "correct", "cosmic", "cotton", "couch", "country",
    "couple", "course", "cousin", "cover", "craft", "crater",
    "credit", "cricket", "crisis", "critic", "cross", "crouch",
    "crowd", "cruise", "crystal", "curtain", "custom", "cycle",
    "damage", "dance", "danger", "daring", "dawn", "debate",
    "decade", "decent", "decide", "decline", "defense", "define",
    "degree", "delay", "deliver", "demand", "denial", "dentist",
    "depart", "depend", "deploy", "deposit", "depth", "deputy",
    "derive", "desert", "design", "detect", "develop", "device",
    "devote", "diamond", "diesel", "differ", "digital", "dignity",
    "dilemma", "dinner", "dinosaur", "direct", "display", "distance",
    "divide", "doctor", "dolphin", "domain", "donate", "donkey",
    "double", "dragon", "drama", "drastic", "dream", "drift",
    "drink", "drive", "drum", "durable", "during", "dwarf",
    "dynamic", "eagle", "early", "earth", "easily", "eclipse",
    "ecology", "economy", "editor", "educate", "effort", "eight",
    "either", "elbow", "elder", "elegant", "element", "elephant",
    "elite", "embrace", "emerge", "emotion", "employ", "enable",
    "endorse", "energy", "enforce", "engage", "engine", "enhance",
    "enjoy", "enough", "enrich", "ensure", "enter", "entire",
    "entry", "envelope", "episode", "equal", "equip", "erosion",
    "escape", "essay", "essence", "estate", "eternal", "evidence",
    "evolve", "exact", "example", "excess", "excite", "exclude",
    "execute", "exercise", "exhaust", "exhibit", "exile", "expand",
    "expect", "expire", "explain", "explore", "export", "expose",
    "extend", "extra", "eyebrow", "fabric", "faculty", "faint",
    "falcon", "family", "famous", "fancy", "fantasy", "fashion",
    "father", "fatigue", "feature", "federal", "fence", "festival",
    "fiber", "fiction", "field", "figure", "filter", "final",
    "finger", "finish", "firefly", "fitness", "flag", "flame",
    "flash", "flavor", "flight", "float", "floor", "flower",
    "fluid", "flush", "focus", "follow", "force", "forest",
    "forget", "fork", "fortune", "forward", "fossil", "foster",
    "found", "fragile", "frame", "freedom", "frequent", "fresh",
    "friend", "fringe", "front", "frozen", "fruit", "gadget",
    "galaxy", "gallery", "garden", "garlic", "garment", "gather",
    "gauge", "general", "genius", "genre", "gentle", "genuine",
    "gesture", "giant", "ginger", "giraffe", "glacier", "glance",
    "globe", "glimpse", "gloom", "glory", "glove", "goddess",
    "golden", "gorilla", "gospel", "gossip", "govern", "grace",
    "grain", "grant", "gravity", "green", "grid", "grocery",
    "group", "guard", "guitar", "habitat", "hammer", "harbor",
    "harvest", "hazard", "height", "helmet", "hero", "hidden",
    "highway", "hockey", "hollow", "honey", "horizon", "horror",
    "hospital", "hotel", "hover", "humble", "humor", "hundred",
    "hungry", "hybrid", "ice", "identify", "idle", "ignore",
    "illegal", "image", "impact", "impose", "improve", "impulse",
    "include", "income", "index", "infant", "inform", "inherit",
    "initial", "inject", "inner", "input", "inquiry", "insect",
    "inside", "inspire", "install", "intact", "interest", "invest",
    "invite", "isolate", "ivory", "jacket", "jaguar", "jewel",
    "journey", "judge", "juice", "jungle", "junior", "justice",
    "kangaroo", "kernel", "kingdom", "kitchen", "kiwi", "knife",
    "label", "ladder", "lake", "language", "laptop", "lateral",
    "latin", "laugh", "laundry", "layer", "leader", "lecture",
    "legend", "leisure", "lemon", "length", "lesson", "letter",
    "level", "liberty", "library", "license", "light", "limb",
    "limit", "link", "liquid", "lizard", "lobster", "local",
    "logic", "lonely", "lottery", "lunar", "luxury", "lyrics",
    "machine", "magnet", "mango", "mansion", "manual", "maple",
    "marble", "march", "margin", "marine", "market", "master",
    "material", "matrix", "meadow", "measure", "medal", "media",
    "melody", "member", "memory", "mention", "mentor", "mercy",
    "method", "middle", "million", "mineral", "minimum", "minute",
    "miracle", "mirror", "misery", "mixture", "mobile", "model",
    "modify", "moment", "monitor", "monkey", "monster", "moral",
    "morning", "mosquito", "mother", "motion", "mountain", "mouse",
    "movie", "much", "multiply", "muscle", "museum", "mushroom",
    "music", "mystery", "myth", "naive", "napkin", "narrow",
    "nasty", "nature", "near", "neglect", "nephew", "nerve",
    "network", "neutral", "noble", "noise", "normal", "north",
    "notable", "nothing", "notice", "novel", "nuclear", "number",
    "nurse", "object", "observe", "obtain", "obvious", "ocean",
    "offense", "offer", "office", "olive", "olympic", "omit",
    "once", "opinion", "oppose", "option", "orange", "orbit",
    "orchard", "order", "organ", "orient", "orphan", "ostrich",
    "other", "outdoor", "output", "outside", "oval", "oven",
    "owner", "oxygen", "oyster", "paddle", "palace", "panda",
    "panel", "panic", "panther", "paper", "parade", "parent",
    "parrot", "party", "patch", "patient", "patrol", "pattern",
    "pause", "peace", "peanut", "pelican", "penalty", "pencil",
    "people", "pepper", "perfect", "permit", "person", "phrase",
    "physical", "piano", "picnic", "picture", "piece", "pilot",
    "pioneer", "pizza", "place", "planet", "plastic", "platform",
    "plunge", "poem", "polar", "police", "popular", "portion",
    "position", "possible", "potato", "pottery", "poverty", "powder",
    "power", "practice", "predict", "prefer", "prepare", "present",
    "pretty", "prevent", "price", "primary", "print", "priority",
    "prison", "private", "prize", "problem", "process", "produce",
    "profit", "program", "project", "promote", "proof", "prosper",
    "protect", "proud", "provide", "public", "pulse", "pumpkin",
    "pupil", "purpose", "puzzle", "pyramid", "quality", "quantum",
    "quarter", "question", "quick", "quote", "rabbit", "raccoon",
    "radar", "radio", "rail", "rainbow", "raise", "ranch",
    "random", "range", "rapid", "rather", "raven", "razor",
    "ready", "reason", "rebel", "rebuild", "recall", "receive",
    "recipe", "record", "recycle", "reduce", "reflect", "reform",
    "region", "regret", "regular", "reject", "relax", "release",
    "relief", "remain", "remember", "remind", "remove", "render",
    "renew", "repair", "repeat", "replace", "report", "require",
    "rescue", "resist", "resource", "response", "result", "retire",
    "retreat", "return", "reveal", "review", "reward", "rhythm",
    "ribbon", "rifle", "right", "rigid", "ring", "ripple",
    "ritual", "river", "road", "rocket", "romance", "rough",
    "round", "royal", "rubber", "runway", "rural", "saddle",
    "safari", "salad", "salmon", "salon", "sample", "satisfy",
    "satoshi", "sauce", "scene", "scheme", "school", "science",
    "scissors", "scorpion", "scout", "screen", "script", "search",
    "season", "second", "secret", "section", "security", "segment",
    "select", "senior", "sentence", "series", "service", "session",
    "settle", "setup", "seven", "shadow", "shaft", "shallow",
    "share", "shell", "sheriff", "shield", "shift", "ship",
    "shiver", "shock", "shoe", "shoot", "short", "shoulder",
    "shrimp", "shrug", "shuffle", "sibling", "siege", "sight",
    "signal", "silent", "silver", "similar", "simple", "since",
    "siren", "sister", "situate", "sketch", "skill", "skin",
    "slender", "slice", "slogan", "slow", "small", "smart",
    "smile", "smoke", "smooth", "snack", "snake", "snap",
    "soccer", "social", "soldier", "solve", "someone", "sort",
    "sound", "source", "south", "space", "spatial", "spawn",
    "special", "sphere", "spider", "spirit", "sponsor", "spoon",
    "sport", "spread", "spring", "square", "squeeze", "stable",
    "stadium", "staff", "stage", "stairs", "stamp", "stand",
    "start", "state", "stay", "stereo", "stick", "stock",
    "stomach", "stone", "stool", "story", "strategy", "street",
    "strike", "strong", "struggle", "student", "stuff", "stumble",
    "style", "subject", "submit", "subtle", "success", "suffer",
    "sugar", "suggest", "summer", "sun", "super", "supply",
    "supreme", "surface", "surge", "surprise", "survey", "suspect",
    "sustain", "swallow", "swamp", "swap", "swear", "sweet",
    "swift", "swim", "switch", "symbol", "symptom", "system",
    "table", "tackle", "talent", "target", "tattoo", "taxi",
    "teach", "team", "tenant", "tennis", "term", "test",
    "text", "thank", "theme", "theory", "thrive", "throw",
    "thunder", "ticket", "tiger", "timber", "tiny", "title",
    "toast", "tobacco", "today", "together", "tomato", "tone",
    "topple", "torch", "tornado", "tortoise", "total", "tourist",
    "toward", "tower", "town", "trade", "traffic", "tragic",
    "train", "transfer", "trash", "travel", "trend", "trial",
    "tribe", "trick", "trigger", "trim", "trophy", "trouble",
    "truck", "truly", "trumpet", "trust", "truth", "tumble",
    "tunnel", "turkey", "turn", "turtle", "twelve", "twenty",
    "twice", "twist", "typical", "ugly", "umbrella", "unable",
    "unaware", "uncle", "uncover", "under", "unfair", "unfold",
    "unhappy", "uniform", "unique", "universe", "unknown", "unlock",
    "until", "unusual", "unveil", "update", "upgrade", "upon",
    "upper", "upset", "urban", "usage", "useful", "useless",
    "usual", "utility", "vacant", "vacuum", "valid", "valley",
    "valve", "vanish", "vapor", "various", "vast", "vault",
    "vehicle", "velvet", "venture", "venue", "verify", "version",
    "veteran", "viable", "victory", "video", "village", "vintage",
    "violin", "virtual", "virus", "visit", "visual", "vital",
    "vivid", "vocal", "voice", "volcano", "volume", "voyage",
    "wage", "wagon", "walnut", "warfare", "warrior", "waste",
    "water", "weapon", "weather", "wedding", "weekend", "welcome",
    "western", "whale", "wheat", "wheel", "whisper", "width",
    "wild", "window", "winter", "wisdom", "witness", "woman",
    "wonder", "wood", "world", "worth", "wrap", "wrestle",
    "wrong", "yard", "young", "youth", "zebra", "zero", "zone",
]


@dataclass
class GeneratedPassword:
    """Container for a generated password and its metadata."""

    password: str
    length: int
    entropy_bits: float
    type: str  # "random" or "passphrase"


class PasswordGenerator:
    """Generate cryptographically secure passwords and passphrases."""

    @staticmethod
    def generate(
        length: int = 20,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_chars: str = "",
    ) -> GeneratedPassword:
        """Generate a random password from the specified character sets.

        At least one character from each enabled set is guaranteed.
        """
        if length < 4:
            raise ValueError("Minimum password length is 4 characters.")

        charset = ""
        required: list[str] = []

        if use_lowercase:
            pool = string.ascii_lowercase
            for ch in exclude_chars:
                pool = pool.replace(ch, "")
            if pool:
                charset += pool
                required.append(secrets.choice(pool))

        if use_uppercase:
            pool = string.ascii_uppercase
            for ch in exclude_chars:
                pool = pool.replace(ch, "")
            if pool:
                charset += pool
                required.append(secrets.choice(pool))

        if use_digits:
            pool = string.digits
            for ch in exclude_chars:
                pool = pool.replace(ch, "")
            if pool:
                charset += pool
                required.append(secrets.choice(pool))

        if use_special:
            pool = "!@#$%^&*()-_=+[]{}|;:,.<>?"
            for ch in exclude_chars:
                pool = pool.replace(ch, "")
            if pool:
                charset += pool
                required.append(secrets.choice(pool))

        if not charset:
            raise ValueError("No characters available after applying exclusions.")

        # Fill remaining length with random choices
        remaining = length - len(required)
        password_chars = required + [secrets.choice(charset) for _ in range(remaining)]

        # Shuffle using Fisher-Yates via secrets
        # secrets.SystemRandom().shuffle is not available, so we sort by random keys
        password_chars.sort(key=lambda _: secrets.randbelow(1_000_000))

        password = "".join(password_chars)
        entropy = length * _log2_safe(len(charset))

        return GeneratedPassword(
            password=password,
            length=length,
            entropy_bits=round(entropy, 2),
            type="random",
        )

    @staticmethod
    def generate_passphrase(
        word_count: int = 5,
        separator: str = "-",
        capitalize: bool = False,
        include_number: bool = True,
    ) -> GeneratedPassword:
        """Generate a diceware-style passphrase from the word list.

        Passphrases are easier to remember and type while maintaining
        high entropy. Each word adds ~log2(wordlist_size) bits of entropy.

        Args:
            word_count: Number of words (minimum 4 for adequate security).
            separator: Character(s) between words.
            capitalize: Capitalize the first letter of each word.
            include_number: Append a random 2-digit number to one word.
        """
        if word_count < 3:
            raise ValueError("Minimum 3 words for a passphrase.")

        words = [secrets.choice(_WORDLIST) for _ in range(word_count)]

        if capitalize:
            words = [w.capitalize() for w in words]

        if include_number:
            idx = secrets.randbelow(len(words))
            number = str(secrets.randbelow(100)).zfill(2)
            words[idx] = words[idx] + number

        passphrase = separator.join(words)

        # Entropy: log2(wordlist_size) per word + log2(100) for optional number
        import math

        bits_per_word = math.log2(len(_WORDLIST))
        entropy = word_count * bits_per_word
        if include_number:
            entropy += math.log2(100) + math.log2(word_count)  # number + position

        return GeneratedPassword(
            password=passphrase,
            length=len(passphrase),
            entropy_bits=round(entropy, 2),
            type="passphrase",
        )

    @staticmethod
    def generate_pin(length: int = 6) -> GeneratedPassword:
        """Generate a numeric PIN.

        PINs are only appropriate for rate-limited interfaces
        (phone lock, ATM). Never use a PIN as a file password.
        """
        if length < 4:
            raise ValueError("Minimum PIN length is 4 digits.")

        import math

        pin = "".join(str(secrets.randbelow(10)) for _ in range(length))
        entropy = length * math.log2(10)

        return GeneratedPassword(
            password=pin,
            length=length,
            entropy_bits=round(entropy, 2),
            type="pin",
        )


def _log2_safe(n: int) -> float:
    """Safe log2 that returns 0 for n <= 0."""
    import math
    return math.log2(n) if n > 0 else 0.0
