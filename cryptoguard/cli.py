"""
CLI Interface for CryptoGuard

Subcommands:
    encrypt         Encrypt a file with a password
    decrypt         Decrypt a file with a password
    hash            Hash a file or string
    check-password  Analyze password strength
    generate-password  Generate a secure password
    generate-passphrase  Generate a diceware-style passphrase
    keys            Key management operations
"""

import argparse
import getpass
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


console = Console()
error_console = Console(stderr=True)


def _get_password(prompt: str = "Password: ", confirm: bool = False) -> str:
    """Securely prompt for a password (no echo)."""
    password = getpass.getpass(prompt)
    if confirm:
        confirm_pw = getpass.getpass("Confirm password: ")
        if password != confirm_pw:
            error_console.print("[red]Passwords do not match.[/red]")
            sys.exit(1)
    return password


# --- Encrypt ---

def cmd_encrypt(args: argparse.Namespace) -> None:
    """Encrypt a file."""
    from cryptoguard.encryptor import FileEncryptor, EncryptionError

    password = _get_password("Encryption password: ", confirm=True)
    enc = FileEncryptor()

    try:
        output = enc.encrypt_file(args.file, password, args.output)
        console.print(f"[green]Encrypted:[/green] {output}")
    except (FileNotFoundError, EncryptionError) as exc:
        error_console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


# --- Decrypt ---

def cmd_decrypt(args: argparse.Namespace) -> None:
    """Decrypt a file."""
    from cryptoguard.encryptor import FileEncryptor, DecryptionError

    password = _get_password("Decryption password: ")
    enc = FileEncryptor()

    try:
        output = enc.decrypt_file(args.file, password, args.output)
        console.print(f"[green]Decrypted:[/green] {output}")
    except (FileNotFoundError, DecryptionError) as exc:
        error_console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


# --- Hash ---

def cmd_hash(args: argparse.Namespace) -> None:
    """Hash a file or string."""
    from cryptoguard.hasher import Hasher

    algorithm = args.algorithm

    if args.string:
        digest = Hasher.hash_string(args.string, algorithm)
        console.print(f"[cyan]{algorithm.upper()}:[/cyan] {digest}")
    elif args.file:
        try:
            digest = Hasher.hash_file(args.file, algorithm)
            console.print(f"[cyan]{algorithm.upper()}:[/cyan] {digest}")
            console.print(f"[dim]File: {args.file}[/dim]")
        except FileNotFoundError as exc:
            error_console.print(f"[red]Error:[/red] {exc}")
            sys.exit(1)
    else:
        error_console.print("[red]Provide --file or --string.[/red]")
        sys.exit(1)

    if args.verify:
        from cryptoguard.hasher import Hasher as H
        match = H.compare_hashes(digest, args.verify)
        if match:
            console.print("[green]Hash matches.[/green]")
        else:
            console.print("[red]Hash does NOT match.[/red]")
            sys.exit(1)


# --- Check Password ---

def cmd_check_password(args: argparse.Namespace) -> None:
    """Analyze password strength."""
    from cryptoguard.password_analyzer import PasswordAnalyzer

    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Enter password to analyze: ")

    report = PasswordAnalyzer.analyze(password)
    crack_time = PasswordAnalyzer.estimate_crack_time(report.entropy_bits)

    # Score color
    if report.score >= 80:
        score_color = "green"
    elif report.score >= 60:
        score_color = "yellow"
    elif report.score >= 40:
        score_color = "dark_orange"
    else:
        score_color = "red"

    table = Table(title="Password Analysis", show_header=False, border_style="dim")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Length", str(report.password_length))
    table.add_row("Score", f"[{score_color}]{report.score}/100[/{score_color}]")
    table.add_row("Rating", f"[{score_color}]{report.rating}[/{score_color}]")
    table.add_row("Entropy", f"{report.entropy_bits} bits")
    table.add_row("Crack Time (10B/s)", crack_time)
    table.add_row("Character Sets", ", ".join(report.character_sets) or "none")
    table.add_row("Common Password", "Yes" if report.is_common else "No")
    table.add_row("Breach DB Hit", "Yes" if report.has_breach_hit else "No")

    console.print(table)

    if report.warnings:
        console.print()
        for w in report.warnings:
            console.print(f"  [yellow]Warning:[/yellow] {w}")

    if report.suggestions:
        console.print()
        for s in report.suggestions:
            console.print(f"  [blue]Suggestion:[/blue] {s}")


# --- Generate Password ---

def cmd_generate_password(args: argparse.Namespace) -> None:
    """Generate a secure random password."""
    from cryptoguard.password_generator import PasswordGenerator

    result = PasswordGenerator.generate(
        length=args.length,
        use_uppercase=not args.no_uppercase,
        use_lowercase=not args.no_lowercase,
        use_digits=not args.no_digits,
        use_special=not args.no_special,
        exclude_chars=args.exclude or "",
    )

    panel = Panel(
        Text(result.password, style="bold green"),
        title="Generated Password",
        subtitle=f"Length: {result.length} | Entropy: {result.entropy_bits} bits",
    )
    console.print(panel)

    if args.count and args.count > 1:
        console.print()
        for i in range(args.count - 1):
            extra = PasswordGenerator.generate(
                length=args.length,
                use_uppercase=not args.no_uppercase,
                use_lowercase=not args.no_lowercase,
                use_digits=not args.no_digits,
                use_special=not args.no_special,
                exclude_chars=args.exclude or "",
            )
            console.print(f"  {extra.password}")


# --- Generate Passphrase ---

def cmd_generate_passphrase(args: argparse.Namespace) -> None:
    """Generate a diceware-style passphrase."""
    from cryptoguard.password_generator import PasswordGenerator

    result = PasswordGenerator.generate_passphrase(
        word_count=args.words,
        separator=args.separator,
        capitalize=args.capitalize,
        include_number=not args.no_number,
    )

    panel = Panel(
        Text(result.password, style="bold green"),
        title="Generated Passphrase",
        subtitle=f"Words: {args.words} | Entropy: {result.entropy_bits} bits",
    )
    console.print(panel)


# --- Key Management ---

def cmd_keys(args: argparse.Namespace) -> None:
    """Key management subcommands."""
    from cryptoguard.key_manager import KeyManager, KeyManagerError

    store_path = Path(args.store) if args.store else None
    km = KeyManager(store_path) if store_path else KeyManager()

    master = _get_password("Master password: ", confirm=(args.key_action == "init"))

    try:
        if args.key_action == "init":
            path = km.initialize_store(master)
            console.print(f"[green]Key store created:[/green] {path}")

        elif args.key_action == "generate":
            key_id = km.generate_key(master, key_id=args.key_id)
            console.print(f"[green]Key generated:[/green] {key_id}")

        elif args.key_action == "list":
            keys = km.list_keys(master)
            if not keys:
                console.print("[dim]No keys in store.[/dim]")
                return

            table = Table(title="Stored Keys")
            table.add_column("Key ID", style="cyan")
            table.add_column("Status")
            table.add_column("Algorithm")
            table.add_column("Created")
            table.add_column("Rotated")

            for k in keys:
                status_style = {
                    "active": "green",
                    "rotated": "yellow",
                    "revoked": "red",
                }.get(k.status, "white")

                table.add_row(
                    k.key_id,
                    f"[{status_style}]{k.status}[/{status_style}]",
                    k.algorithm,
                    k.created_at[:19],
                    (k.rotated_at or "")[:19],
                )

            console.print(table)

        elif args.key_action == "rotate":
            if not args.key_id:
                error_console.print("[red]--key-id is required for rotate.[/red]")
                sys.exit(1)
            new_id = km.rotate_key(master, args.key_id)
            console.print(f"[green]Key rotated. New key:[/green] {new_id}")

        elif args.key_action == "revoke":
            if not args.key_id:
                error_console.print("[red]--key-id is required for revoke.[/red]")
                sys.exit(1)
            km.revoke_key(master, args.key_id)
            console.print(f"[yellow]Key revoked:[/yellow] {args.key_id}")

        else:
            error_console.print(f"[red]Unknown key action: {args.key_action}[/red]")
            sys.exit(1)

    except KeyManagerError as exc:
        error_console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


# --- Argument Parser ---

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="cryptoguard",
        description="CryptoGuard - Cryptographic Security Toolkit",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s 1.0.0"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("file", help="File to encrypt")
    p_enc.add_argument("-o", "--output", help="Output file path")
    p_enc.set_defaults(func=cmd_encrypt)

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("file", help="File to decrypt")
    p_dec.add_argument("-o", "--output", help="Output file path")
    p_dec.set_defaults(func=cmd_decrypt)

    # hash
    p_hash = subparsers.add_parser("hash", help="Hash a file or string")
    p_hash.add_argument("-f", "--file", help="File to hash")
    p_hash.add_argument("-s", "--string", help="String to hash")
    p_hash.add_argument(
        "-a", "--algorithm",
        choices=["sha256", "sha512", "blake2b"],
        default="sha256",
        help="Hash algorithm (default: sha256)",
    )
    p_hash.add_argument(
        "-v", "--verify", help="Expected hash to verify against"
    )
    p_hash.set_defaults(func=cmd_hash)

    # check-password
    p_check = subparsers.add_parser(
        "check-password", help="Analyze password strength"
    )
    p_check.add_argument(
        "password", nargs="?", default=None,
        help="Password to analyze (omit for secure prompt)",
    )
    p_check.set_defaults(func=cmd_check_password)

    # generate-password
    p_gen = subparsers.add_parser(
        "generate-password", help="Generate a secure password"
    )
    p_gen.add_argument(
        "-l", "--length", type=int, default=20,
        help="Password length (default: 20)",
    )
    p_gen.add_argument("-c", "--count", type=int, default=1, help="Number to generate")
    p_gen.add_argument("--no-uppercase", action="store_true")
    p_gen.add_argument("--no-lowercase", action="store_true")
    p_gen.add_argument("--no-digits", action="store_true")
    p_gen.add_argument("--no-special", action="store_true")
    p_gen.add_argument("--exclude", help="Characters to exclude")
    p_gen.set_defaults(func=cmd_generate_password)

    # generate-passphrase
    p_phrase = subparsers.add_parser(
        "generate-passphrase", help="Generate a diceware-style passphrase"
    )
    p_phrase.add_argument(
        "-w", "--words", type=int, default=5,
        help="Number of words (default: 5)",
    )
    p_phrase.add_argument(
        "-s", "--separator", default="-",
        help="Word separator (default: -)",
    )
    p_phrase.add_argument("--capitalize", action="store_true")
    p_phrase.add_argument("--no-number", action="store_true")
    p_phrase.set_defaults(func=cmd_generate_passphrase)

    # keys
    p_keys = subparsers.add_parser("keys", help="Key management")
    p_keys.add_argument(
        "key_action",
        choices=["init", "generate", "list", "rotate", "revoke"],
        help="Key management action",
    )
    p_keys.add_argument("--key-id", help="Key identifier")
    p_keys.add_argument("--store", help="Path to key store file")
    p_keys.set_defaults(func=cmd_keys)

    return parser


def main(argv: Optional[list[str]] = None) -> None:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)
