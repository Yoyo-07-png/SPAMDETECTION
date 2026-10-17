import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from services.scanner import HeaderScanner, BodyScanner

console = Console()

SEVERITY_STYLE = {"HIGH": "bold red", "MODERATE": "yellow", "NEUTRAL": "cyan"}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="emailscan",
        description="Scores an email's headers for signs of spam or spoofing.",
        epilog="Example:\n  emailscan suspicious.eml -v",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("filepath", type=Path, metavar="EMAIL_FILE",
                        help="path to the .eml file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show individual warnings")
    parser.add_argument("-t", "--test", action="store_true",
                        help="get a sneak peek at the body scanner!")
    return parser


def print_scores(scores: dict):
    table = Table(title="", title_style="bold", box=None)
    table.add_column("Check")
    table.add_column("Score", justify="right")

    for label, value in scores.items():
        is_final = label == "FINAL_HEADER_SCORING"
        table.add_row(
            f"[bold]{label}[/]" if is_final else label,
            f"[bold green]{value:.2f}[/]" if is_final else f"{value:.2f}",
        )
    console.print(table)


def print_details(details: list[str]):
    if not details:
        console.print("[green]No warnings.[/]")
        return
    for line in details:
        # "WARNING=HIGH | FAILED SPF..." -> level "HIGH", message "FAILED SPF..."
        left, _, message = line.partition("|")
        level = left.split("=")[-1].strip()
        style = SEVERITY_STYLE.get(level, "")
        console.print(f"[{style}]{level:<8}[/] {message.strip()}")
        
def print_body_details(bodyScanner: BodyScanner):
    details = bodyScanner.parse_html_body()
    
    if not details:
        console.print("[yellow]No Body Details could be found from HTML.")
        return
    for value, keys in details.items():
        console.print(f"[bold]{value}[/]:")
        for index, key in enumerate(keys):
            console.print(f"\t[blue]{index}[/] : {key}\n")
            
        console.print("\n\n\n")


def main():
    args = build_parser().parse_args()

    if not args.filepath.is_file():
        console.print(f"[red]Error:[/] file not found: {args.filepath}")
        sys.exit(1)

    scanner = HeaderScanner(args.filepath)
    scanner.extract_email()
    
    if not scanner.email:
        console.print("[red]Error:[/] couldn't extract the sender address. "
                      "Check that the file is a valid email.")
        sys.exit(1)

    console.rule("HEADER CHECK")
    scanner.do_header_check()
    
    if isinstance(scanner.get_header_score(), str):
        console.print("[red]Error:[/] [bold]HEADER SCANNING FAILED! \n[/]Couldn't extract important info from the email.\n"
                      "It may be curropted. Check that the file format is correct.")
        
        sys.exit(1)
    
    print_scores(scanner.get_header_score())

    if args.verbose:
        console.rule("Details")
        print_details(scanner.details)
    else:
        n = len(scanner.details)
        console.print(f"\n{n} warning(s). Run with [bold]-v[/] to see them.")
    
    if args.test:
        body_scanner = BodyScanner(args.filepath)
        body_scanner.extract_email()
        body_scanner.helper_get_body()
        console.rule("BODY - (STILL IN DEVELOPMENT)")
        print_body_details(body_scanner)


if __name__ == "__main__":
    main()