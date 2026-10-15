import argparse
import json
from services.scanner import HeaderScanner
from pathlib import Path

parser = argparse.ArgumentParser(
    prog='Email Scam detector or whatever',
    description="this is supposed to detect smelly emails. big emphasis on supposed to.",
    epilog="I don't know what the epilog property does but it sounds fancy so I'll use it ngl."
)

def main():
    parser.add_argument('filepath'
                        , type=Path)
    parser.add_argument('-v', '--verbose', action='store_true')
    
    
    args = parser.parse_args()
    
    if args.filepath:
        headerScan = HeaderScanner(args.filepath)
        headerScan.extract_email()
        if not headerScan.email:
            print(f"Couldn't extract the email properly. Can you perhaps check the address for it?")
            return
        
        headerScan.do_header_check()
        headerScore = headerScan.get_header_score()
        
        print(headerScore) # for now:
        print(headerScan.details)


if __name__ == "__main__":
    main()