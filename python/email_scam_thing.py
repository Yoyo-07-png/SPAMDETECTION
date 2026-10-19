import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from services.scanner import HeaderScanner, BodyScanner

console = Console()

SEVERITY_STYLE = {"HIGH": "bold red", "MODERATE": "yellow", "NEUTRAL": "cyan"}


def terminal_safe(value: str) -> str:
    encoding = getattr(console.file, "encoding", None)
    cleaned = "".join(
        character
        if character in "\n\t" or ord(character) >= 32 and ord(character) != 127
        else " "
        for character in value
    )
    if encoding:
        return cleaned.encode(encoding, errors="replace").decode(encoding)
    return cleaned


def build_parser():
    parser = argparse.ArgumentParser(
        prog="emailscan",
        description="Scores email headers and optionally analyzes body content.",
        epilog="Example:\n  emailscan suspicious.eml -v -t",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("filepath", type=Path, metavar="EMAIL_FILE",
                        help="path to the .eml file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show individual warnings")
    parser.add_argument("-t", "--test", action="store_true",
                        help="show body classification and model evidence")
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
    console.print(Panel(
        table,
        title="[bold cyan]HEADER CHECK",
        border_style="cyan",
        padding=(0, 1),
    ))


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
        
def print_body_details(body_scanner: BodyScanner):
    analysis = body_scanner.get_model_analysis()
    if isinstance(analysis, str):
        console.print(Panel(
            Text(analysis, style="bold red"),
            title="[bold red]MODEL UNAVAILABLE",
            border_style="red",
        ))
    else:
        spam_probability = analysis["spam_probability"]
        bar_width = 16
        filled = round(spam_probability * bar_width)
        prediction = Text()
        prediction.append(
            f"{analysis['label'].upper()}",
            style="bold red" if analysis["label"] == "Spam" else "bold green",
        )
        prediction.append(
            f"\nSpam {spam_probability:.1%} | Ham "
            f"{analysis['ham_probability']:.1%}\n\n",
            style="white",
        )
        prediction.append("Spam likelihood\n", style="dim")
        prediction.append("#" * filled, style="red")
        prediction.append("-" * (bar_width - filled), style="dim")
        prediction.append(f"\n\n{analysis['matched_features']:,} features matched", style="dim")
        classification_panel = Panel(
            prediction,
            title="[bold magenta]BODY CLASSIFICATION",
            border_style="magenta",
            expand=True,
            padding=(1, 2),
        )

        evidence = Table(
            title="Words & phrases influencing the result",
            title_style="bold",
            header_style="bold cyan",
            border_style="blue",
            expand=True,
        )
        evidence.add_column("Spam +", style="bold red")
        evidence.add_column("Impact", justify="right", no_wrap=True)
        evidence.add_column("Ham +", style="bold green")
        evidence.add_column("Impact", justify="right", no_wrap=True)
        spam_items = analysis["spam_evidence"]
        ham_items = analysis["ham_evidence"]
        for index in range(max(len(spam_items), len(ham_items))):
            spam_item = spam_items[index] if index < len(spam_items) else None
            ham_item = ham_items[index] if index < len(ham_items) else None
            evidence.add_row(
                Text(terminal_safe(spam_item["term"])) if spam_item else "",
                f"{spam_item['log_odds']:+.3f}" if spam_item else "",
                Text(terminal_safe(ham_item["term"])) if ham_item else "",
                f"{ham_item['log_odds']:+.3f}" if ham_item else "",
            )
        if evidence.row_count:
            evidence_panel = Panel(
                evidence,
                border_style="blue",
                expand=True,
                padding=(0, 1),
            )
        else:
            evidence_panel = Panel(
                Text("No in-vocabulary terms contributed to this estimate.", style="dim"),
                border_style="dim",
                expand=True,
                padding=(1, 2),
            )

        report = Table.grid(expand=True, padding=(0, 1))
        report.add_column(ratio=1)
        report.add_column(ratio=2)
        report.add_row(classification_panel, evidence_panel)
        console.print(report)
        console.print(
            "[dim]Token impacts are model evidence, not guaranteed causes. "
            "Naive Bayes probabilities are not calibrated real-world certainty.[/]"
        )


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
        console.rule("[bold cyan]BODY ANALYSIS")
        print_body_details(body_scanner)


if __name__ == "__main__":
    main()