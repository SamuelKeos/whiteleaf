import json
import requests
import splunklib.client as client
import os, sys
import splunk.Intersplunk as intersplunk
from urllib.parse import urlparse
from splunklib.searchcommands import ReportingCommand, Configuration, Option, validators

@Configuration()
class ExternalNotableCommentCommand(ReportingCommand):
    external_url = "http://35.87.82.114:8080"
    verify_ssl = Option(require=False, default=True, validate=validators.Boolean())

    def generate(self):
        # Collect all events from the search
        events = [dict(event) for event in self._events]
        

        # Read results from Splunk
        results, dummyresults, settings = intersplunk.getOrganizedResults()

        if not results:
            intersplunk.outputResults([])
            sys.exit(0)

        values = [row["orig_source"] for row in results if "orig_source" in row]

        if not values:
            intersplunk.outputResults([{"error": "No 'prompt' field found in results"}])
            sys.exit(0)

        params = {
            "prompts": ",".join(map(str, values)),
            "whiteleafuc": "triage"
                 }
        
        # Send data to external HTTP server
        try:
            response = requests.post(
                self.external_url,
                json=values,
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            response_data = response.json()
        except Exception as e:
            self.logger.error(f"External HTTP request failed: {str(e)}")
            # Pass through original events on failure
            yield from (event for event in events)
            return

        # Get Splunk session metadata
        metadata = self._metadata
        session_key = metadata.searchinfo.session_key
        server_uri = metadata.searchinfo.server_uri

        # Connect to Splunk service
        parsed_uri = urlparse(server_uri)
        service = client.connect(
            token=session_key,
            host=parsed_uri.hostname,
            port=parsed_uri.port,
            scheme=parsed_uri.scheme
        )

        # Process responses and update notable events
        for item in response_data:
            event_id = item.get('event_id')
            comment = item.get('comment')
            
            if not event_id or not comment:
                continue
                
            try:
                service.post(
                    'services/notable_update',
                    comment=comment,
                    event_ids=event_id
                )
                self.logger.info(f"Added comment to notable event: {event_id}")
            except Exception as e:
                self.logger.error(f"Notable update failed for {event_id}: {str(e)}")

        # Pass through original events
        yield from (event for event in events)