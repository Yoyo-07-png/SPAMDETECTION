import base64
import os
import re
import email
import tldextract
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path


# TODO tmr:
# 1: create a cli interface with argparse which takes eml files. COMPLETED!
# 2: fix domain alignment scan exiting early for no_dmarc
# ^ --> do that by holding on to the penalty... if alignment completely fails afterwards, raise the penalty from 70 to a 100.
# 3: fix the detail report for the two previous scans
class HeaderScanner():
    
    
    def __init__(self, raw_email: str | bytes | os.PathLike[str] | None):
        self.raw_email = raw_email
        self.email = None
        
        self.from_header = None
        self.dkim_headers = []
        
        self.route_score = None
        self.authentication_score = None
        self.domain_score = None
        
        self.spf_score = None
        self.dkim_score = None
        self.dmarc_score = None
        
        self.details = []
    def extract_email(
        self, raw_email: str | bytes | os.PathLike[str] | None = None
    ):
        
        source = self.raw_email if raw_email is None else raw_email
        if source is None:
            return "There's no provided email!"
        
        if isinstance(source, bytes):
            raw_bytes = source
        elif isinstance(source, os.PathLike):
            raw_bytes = Path(source).read_bytes()
        elif isinstance(source, str):
            raw_bytes = base64.urlsafe_b64decode(source)
        else:
            raise TypeError("Email input must be base64 text, bytes, or a path.")

        msg = email.message_from_bytes(raw_bytes)
        
        self.email = msg
    
    def helper_get_received(self):
        
        if self.email is None:
            return "Email not provided!"
        
        received_headers = self.email.get_all("Received")
        return received_headers
    
    def helper_get_auth_results(self):
        
        if self.email is None:
            return "Email not provided!"
        
        received_header = self.email.get("Authentication-Results")
        return received_header
    
    def check_received(self, received_headers=None, max_delay_seconds=300, max_length=30):
    
        if not received_headers:
            received_headers = self.helper_get_received()
            
        if not received_headers:
            # Missing evidence is unknown, not a clean score.
            return {
                "score": None,
                "score_scale": "risk_out_of_10",
                "evaluated": False,
                "flags": {},
                "details": ["No Received headers found."],
            }
        
        WEIGHTS = {
            "time_travel" : 40,
            "spike": 25,
            "a_lot_of_routes": 20,
            "unparsable_on_time": 15
        }
        
        suspicious_flags = {
            name: {
                "triggered" : False,
                "weight" : weight,
                "result" : [],
                "details" : "Not Evaluated."
            } for name, weight in WEIGHTS.items()
        }
            
        if len(received_headers) > max_length:
            
            suspicious_flags["a_lot_of_routes"]["triggered"] = True
            suspicious_flags["a_lot_of_routes"]["result"] = [len(received_headers)]
            suspicious_flags["a_lot_of_routes"]["details"] = (
                f"This email has more than the maximum configured amount for received headers ({max_length}), which is: {len(received_headers)}"
            )
            
        # received headers are a bunch of strings in a list.
        dates = []
        
        for received in received_headers:
            try:
                
                date = received.rsplit(";" , 1)[1].strip()
                datetime_object = parsedate_to_datetime(date)
                
                ## IMPORTANT: THIS ASSUMES ALL TIMEZONES ARE COMPARED IN UTC.
                if datetime_object.tzinfo is None:
                    datetime_object = datetime_object.replace(tzinfo=timezone.utc)
                
                dates.append(datetime_object)
                
            except (IndexError, TypeError, ValueError):
                suspicious_flags["unparsable_on_time"]["triggered"] = True
        
        dates.reverse()    # reverse in place needed here:        
        for i in range(1, len(dates)):
            prev_hop = dates[i - 1]
            curr_hop = dates[i]
            
            time_diff = (curr_hop - prev_hop).total_seconds()
            
            # check for time travel: # indicates forged headers:
            # a small time drift is needed for mail transfer agents.
            if (time_diff) < -10:
                
                if not suspicious_flags["time_travel"]["triggered"]:
                    suspicious_flags["time_travel"]["triggered"] = True
                    
                suspicious_flags["time_travel"]["result"].append(             
                    f"Chronology Error: Hop {i} appeared {abs(time_diff)}s BEFORE Hop {i - 1}"
                )
                
            # check for unusually long delays or spikes:
            if (time_diff) > max_delay_seconds:
                
                if not suspicious_flags["spike"]["triggered"]:
                    suspicious_flags["spike"]["triggered"] = True
                
                suspicious_flags["spike"]["result"].append(
                    f"Latency Spike: Hop {i} took {time_diff}s to process after Hop {i - 1}"
                )
            
        if suspicious_flags["time_travel"]["result"]:
            suspicious_flags["time_travel"]["details"] = (
                f"""time travel warning issued: some later hoop/s have earlier dates than previous ones,
                with a difference larger than the configured small time drift. """
        )
            
        if suspicious_flags["spike"]["result"]:
            suspicious_flags["spike"]["details"] = (
                f"""time spikes, over the configured time limit, were caught."""
            )
            
        received_risk_points = sum(
            flag["weight"]
            for flag in suspicious_flags.values()
            if flag["triggered"]
        )
        # The Received-check weights total 100, so dividing by 10 maps the
        # risk points to a consistent 0-10 scale.
        self.route_score = received_risk_points
                
        return {
            "score": round(float(received_risk_points), 1),
            "score_scale": "risk_out_of_100",
            "evaluated": True,
            "flags": suspicious_flags,
        }
    
    def check_authentication_results(self, authentication_header=None):
        
        WEIGHTS = {
        "failed_dkim": 50,
        "failed_spf": 50,
        }
        
        # IF ANY IS ABSENT, CHANGE THEIR WEIGHTS TO THE HALF, AND COUNT IT AS A FAIL! THIS IS REALLY IMPORTANT >:|
        
        suspicious_flags = {
                name: {
                    "triggered": False,
                    "weight": weight,
                    "result": None,
                    "details": "Not evaluated.",
                }
                for name, weight in WEIGHTS.items()
        }
        
        details = []
        
        DKIM_PATTERN = re.compile(r'(?i)(?<![\w-])dkim=(pass|fail|none|neutral|policy|temperror|permerror)\b[^;]*?header\.[di]=@?([^\s;]+)')
        SPF_PATTERN = re.compile(r'(?i)(?<![\w-])spf=(pass|fail|softfail|neutral|none|temperror|permerror)\b[^;]*?smtp\.mailfrom=([^\s;]+)')
        # dmarc is needed for domain alignment, and will not be used for authentication scoring.
        DMARC_PATTERN = re.compile(r'(?i)(?<![\w-])dmarc=(pass|fail|bestguesspass|none)\b[^;]*?\(p=(\w+)[^)]*\)[^;]*?header\.from=([^\s;]+)')
        
        if not authentication_header:
            authentication_header = self.helper_get_auth_results()
            
        if not authentication_header:
            for name in suspicious_flags:
                suspicious_flags[name]["details"] = "Authentication header is missing."
                
            return {
                "score": None,
                "score_scale": "risk_out_of_10",
                "evaluated": False,
                "flags": suspicious_flags,
                "details": ["No Authentication-Results header was available."],
            }
        
        # get rid of folding/multiple lines:
        authentication_header = re.sub(r'\r?\n\s+', ' ', authentication_header)
        
        parsed_results = {
        "failed_dkim": DKIM_PATTERN.findall(authentication_header),
        "failed_spf": SPF_PATTERN.findall(authentication_header),
        }
        
        # examples of the regex working :3 (god why is it so hard) -> 
        # DKIM: [('pass', 'cio113400.neon.tech'), ('pass', 'mailgun.org')]
        # SPF:  [('pass', 'postmaster@cio113400.neon.tech')]
        # DMARC: [('pass', 'REJECT', 'neon.tech')]
        for flag_name, results in parsed_results.items():
            if not results:
                suspicious_flags[flag_name]["triggered"] = True
                suspicious_flags[flag_name]["weight"] = WEIGHTS[flag_name] / 2
                suspicious_flags[flag_name]["details"] = (
                    "Could not find a parseable authentication result."
                )
                
                details.append(
                f"{flag_name}: no parseable result found."
                )
                
                continue
            
            # necessary for multiple passes from dkim if available.
            statuses = [result[0].lower() for result in results]
            
            if flag_name == "failed_dkim":
                self.dkim_score = results
                identifiers = [result[1] for result in results]
            elif flag_name == "failed_spf":
                self.spf_score = results
                identifiers = [result[1] for result in results]
                
            failed_statuses = [status for status in statuses if status != "pass"]
            
            if failed_statuses:
                suspicious_flags[flag_name]["triggered"] = True
                suspicious_flags[flag_name]["result"] = ", ".join(statuses)
                suspicious_flags[flag_name]["details"] = (
                    f"Authentication did not pass: {', '.join(failed_statuses)}. "
                    f"Identity: {', '.join(identifiers)}."
                )
                details.append(
                    f"{flag_name}: {suspicious_flags[flag_name]['details']}"
                )
                
            else:
                suspicious_flags[flag_name]["result"] = ", ".join(statuses)
                suspicious_flags[flag_name]["details"] = (
                f"Authentication passed for {', '.join(identifiers)}."
                )

        risk_points = sum(
            flag["weight"]
            for flag in suspicious_flags.values()
            if flag["triggered"]
        )
        
        self.authentication_score = risk_points
        
        # Will be used in the second function.
        self.dmarc_score = DMARC_PATTERN.findall(authentication_header)
        
        return {
            "score": round(float(risk_points), 1) if risk_points is not None else None,
            "score_scale": "risk_out_of_100",
            "evaluated": True,
            "flags": suspicious_flags,
            "details": details,
        }
        
    def helper_get_from(self):
        
        if not self.email:
            return None

        from_header = self.email.get("From", [])
        return_path_header = self.email.get_all("Return-Path" , [])
        return [from_header, return_path_header]
    
    def helper_get_dkim_signatures(self):
        
        if not self.email:
            return None
        
        dkim_headers = self.email.get_all("DKIM-Signature", [])
        return dkim_headers
    
    def check_domain_alignment(self):
        
        additional_details = []
        
        if self.from_header is None:
            self.from_header = self.helper_get_from()
            
        if not self.dkim_headers:
            self.dkim_headers = self.helper_get_dkim_signatures()
            
        WEIGHTS = {
            # Techincally, the end user (their inbox, can't see a spam email with reject)
            "dmarc_pass_policy_none": 50,
            "spf_dkim_dont_exist_both": 0, # already flagged above.
            "no_dmarc": 70,
            "dmarc_fail": 100
        }
        
        suspicious_flags = {
            name : {
                "Triggered": False,
                "Weight": weight,
                "Result": None, # may not be used, keep it for compatability later on.
                "Details": None # ^
            } for name, weight in WEIGHTS.items()
        }
        
        # DMARC: [('pass', 'REJECT', 'neon.tech')]
        dmarc_result = self.dmarc_score
        if not dmarc_result: # []
            suspicious_flags["no_dmarc"]["Triggered"] = True
            self.domain_score = suspicious_flags["no_dmarc"]["Weight"]
            self.details.append(
                f"WARNING=MODERATE | No DMARC exists for this email. Suspicious emails and spam emails have a tendency to leave some flags out. Take this email with caution!"
            )
            return suspicious_flags
            
        if dmarc_result[0][1].lower() == 'none':
            suspicious_flags["dmarc_pass_policy_none"]["Triggered"] = True
            self.domain_score = suspicious_flags["dmarc_pass_policy_none"]["Weight"]
            self.details.append(
                f" WARNING=MODERATE | The DMARC policy of this email is none, which allows for spoofing."
            )
            
            return suspicious_flags
        
        spf_result = self.spf_score
        dkim_result = self.dkim_score
        
        # both are omitted:
        if not spf_result and not dkim_result:
            suspicious_flags["spf_dkim_dont_exist_both"]["Triggered"] = True
            self.domain_score = suspicious_flags["spf_dkim_dont_exist_both"]["Weight"]
            # A warning for this should be issued in the previous (Auth) scan.
            
            return suspicious_flags
        
        # only one of them is needed to pass alignment.
        alignment = []
        if spf_result or dkim_result:
            # first check on SPF:
            if spf_result:
                if not any(not arg for arg in self.from_header):
                    spf_alignment = self.check_relaxed(
                        self.normalize_email(self.from_header[0]),
                        self.normalize_email(self.from_header[1][0])
                    )
                    
                    alignment.append(spf_alignment) if spf_alignment["is_aligned"] else None
                    self.details.append(
                        f" WARNING=NEUTRAL | DMARC alignment passed with SPF --> FROM DOMAIN: {spf_alignment['from_org_domain']} | RETURN-PATH DOMAIN: {spf_alignment['compared_value_domain']}"
                    ) if spf_alignment["is_aligned"] else None
                else:
                    self.details.append(
                        f" WARNING=MODERATE | not all headers needed for SPF alignment are present, and therefore the scanner couldn't continue checking for SPF."
                    )    
                    
            # if the SPF check failed, move on to DKIM:
            if dkim_result and self.dkim_headers:
                # again: 
                # DMARC: [('pass', 'REJECT', 'neon.tech')]
                domain = dmarc_result[0][2]
                dkim_found = False
                for header in self.dkim_headers:
                    parts = header.split(";")
                    for part in parts:
                        part = part.strip()
                        print(part)
                        if part.startswith("d="):
                            dkim_alignment = self.check_relaxed(
                                part.split("=", 1)[1].strip(),
                                domain
                            )
                            
                            if dkim_alignment['is_aligned']:
                                alignment.append(dkim_alignment)
                                
                                self.details.append(
                                    f" WARNING=NEUTRAL | DMARC alignment passed with DKIM --> FROM DOMAIN: {dkim_alignment['from_org_domain']} | {dkim_alignment['compared_value_domain']}"
                                )
                                dkim_found = True
                                break
                    
                    if dkim_found:
                        break   
            else:
                additional_details.append(
                    f" WARNING=MODERATE | not all headers needed for DKIM alignment are present, and therefore the scanner couldn't continue checking for DKIM."
                )
                
        if not alignment:
            suspicious_flags["dmarc_fail"]["Triggered"] = True
            self.domain_score = suspicious_flags["dmarc_fail"]["Weight"]
            self.details.append(
                f" WARNING=CRITICAL | ALIGNMENT FAILED ON BOTH DKIM AND SPF."
            )
            
            return suspicious_flags
        
        else:
            self.details.append(
                f" WARNING=NEUTRAL | Alignment passed for the given email!"
            )
            
            score = sum(
                flag["Weight"]
                for flag in suspicious_flags.values()
                if flag["Triggered"]
            )
            
            self.domain_score = score
            return suspicious_flags
                    
         
            
                
            
    def check_relaxed(self, from_domain, compared_value):
        # this function takes what comes after the @
        # this is already done by normalize_email() beforehand.
        ext_from = tldextract.extract(from_domain)
        ext_return = tldextract.extract(compared_value)
        
        org_from = f"{ext_from.domain}.{ext_from.suffix}"
        org_return = f"{ext_return.domain}.{ext_return.suffix}"
        is_aligned = org_from.lower() == org_return.lower()
        
        return {
            "from_org_domain": org_from,
            "compared_value_domain": org_return,
            "is_aligned": is_aligned
        }        

    def normalize_email(self, raw_value):
        if '<' in raw_value and '>' in raw_value:
            raw_value = raw_value.split('<')[1].split('>')[0]
            
        clean_email = raw_value.strip('<>" ')
        if '@' in clean_email:
            clean_email = clean_email.split('@')[-1]
        
        return clean_email
    
    def do_header_check(self):
        # This just fires the three scanners.
        self.check_received()
        self.check_authentication_results()
        self.check_domain_alignment()
    
    def get_header_score(self):
        # Assuming all checks pass:
        if self.domain_score is None or self.route_score is None or self.authentication_score is None:
            return f"One of the authentications didn't pass successfully."    
        
        WEIGHTS = {
            "route_check":0.5,
            "authentication_check":3,
            "alignment_check":2.5
        }
        
        calculate_route = self.route_score/200 if self.route_score != 0 else 0
        calculate_authentication = (3*self.authentication_score)/100 if self.authentication_score != 0 else 0
        calculate_alignment = (2.5*self.domain_score)/100 if self.domain_score != 0 else 0
        
        results = {
            "Route score: (hopping, time-travel)":calculate_route,
            "Authentication score: (SPF, DKIM)":calculate_authentication,
            "Alignment score: (DMARC check for SPF and DKIM)":calculate_alignment
        }
        
        sorted_results = sorted(results.items(), key=lambda item: item[1], reverse=True)
        
        final_header_score = sum(
            score
            for _, score in sorted_results
        )
        
        return {
            **{result:value for result, value in sorted_results},
            "FINAL_HEADER_SCORING":round(final_header_score ,1)
        }