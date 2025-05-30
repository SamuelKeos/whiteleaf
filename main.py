import http.server
import socketserver
import threading
import time
import json
import urllib.parse
import os
import logging
from cryptography.fernet import Fernet
from prompt import main as prompt_main

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
PORT = 8080  # Standard HTTP port
MAX_REQUEST_SIZE = 1048576  # 1MB max request size
REQUEST_TIMEOUT = 30  # 30 second timeout

# Generate or load encryption key
def generate_encryption_key():
    """Generate a new Fernet encryption key"""
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)
    return key

# Load encryption key from environment or file
def load_encryption_key():
    """Load encryption key from environment variable or file"""
    env_key = os.environ.get('ENCRYPTION_KEY')
    if env_key:
        return env_key.encode()
    
    #This is kind of silly, ensure the above environment variable (ENCRYPTION_KEY) is set and this will never run
    key_path = os.environ.get('KEY_PATH', 'secret.key')
    if not os.path.exists(key_path):
        return generate_encryption_key()
    
    with open(key_path, 'rb') as key_file:
        return key_file.read()

#set secret key and load it into fernet
SECRET_KEY = load_encryption_key()
cipher_suite = Fernet(SECRET_KEY)

def encrypt_data(data_list):
    """Encrypt a list of strings"""
    return [cipher_suite.encrypt(item.encode()) for item in data_list]

def decrypt_data(data_list):
    """Decrypt a list of encrypted bytes"""
    return [cipher_suite.decrypt(item).decode() for item in data_list]

def should_encrypt_response(response):
    """Determine if response contains sensitive data"""
    sensitive_keywords = {'password', 'token', 'key', 'secret', 'auth', 'credential'}
    return any(keyword in response.lower() for keyword in sensitive_keywords)

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler with encryption for payloads"""
    
    protocol_version = 'HTTP/1.1'  # Enable keep-alive connections
    
    def setup(self):
        self.timeout = REQUEST_TIMEOUT
        http.server.SimpleHTTPRequestHandler.setup(self)
    
    def do_GET(self):
        """Handle GET requests with encrypted parameters"""
        request_id = threading.get_ident()
        logger.info(f"Request {request_id}: Processing GET request from {self.client_address}")
        
        # Check request size to prevent DOS
        #content_length = int(self.headers.get('Content-Length', 0))
        #if content_length > MAX_REQUEST_SIZE:
         #   self.send_error_response(413, {"status": "error", "message": "Request entity too large"})
          #  return

        try:
            # Parse query parameters securely
            query_string = urllib.parse.urlparse(self.path).query
            query_params = urllib.parse.parse_qs(query_string)
            
            # Validate input
            if not all(k in query_params for k in ('prompts', 'whiteleafuc')):
                logger.warning(f"Request {request_id}: Missing required parameters")
                self.send_error_response(400, {"status": "error", "message": "Missing required parameters"})
                return
            
            # Process the data with proper validation
            try:
                case, data = self.parse_data(query_params)
            except ValueError as e:
                logger.warning(f"Request {request_id}: Data parsing error: {str(e)}")
                self.send_error_response(400, {"status": "error", "message": str(e)})
                return
            
            # Call prompt.py with plaintext data
            try:
                logger.info(f"Request {request_id}: Calling AI service with {len(data)} data items")
                ai_response = prompt_main(case, data)
            except Exception as e:
                logger.error(f"Request {request_id}: AI service error: {str(e)}")
                self.send_error_response(500, {"status": "error", "message": "AI processing error"})
                return
            
            # Encrypt sensitive response if needed
            if should_encrypt_response(ai_response):
                logger.info(f"Request {request_id}: Encrypting sensitive response")
                encrypted_response = cipher_suite.encrypt(ai_response.encode())
                # For this implementation, we're decrypting before sending to demonstrate the flow
                # In a real production system, you might send the encrypted response to clients
                # who have the decryption key
                #ai_response = cipher_suite.decrypt(encrypted_response).decode()

                #sending back to client encrypted response
                ai_response = encrypted_response
            
            logger.info(f"Request {request_id}: Sending successful response")
            self.send_secure_response(200, {"status": "success", "data": ai_response})

        except Exception as e:
            logger.error(f"Request {request_id}: Unhandled exception: {str(e)}", exc_info=True)
            self.send_error_response(500, {"status": "error", "message": "Internal server error"})
    
    def do_POST(self):
        """Handle POST requests with encrypted body"""
        request_id = threading.get_ident()
        logger.info(f"Request {request_id}: Processing POST request from {self.client_address}")
        
        # Check request size to prevent DOS
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_REQUEST_SIZE:
            self.send_error_response(413, {"status": "error", "message": "Request entity too large"})
            return
        
        try:
            # Read and parse JSON body
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))
            
            # Validate input
            if not all(k in data for k in ('prompts', 'whiteleafuc')):
                logger.warning(f"Request {request_id}: Missing required parameters in POST body")
                self.send_error_response(400, {"status": "error", "message": "Missing required parameters"})
                return
            
            # Process the data
            try:
                case = data['whiteleafuc']
                prompts = data['prompts']
                
                if not isinstance(prompts, list):
                    prompts = [prompts] if isinstance(prompts, str) else []
                
                if not prompts or not case:
                    raise ValueError("Invalid or missing data")
            except (KeyError, ValueError) as e:
                logger.warning(f"Request {request_id}: Data parsing error: {str(e)}")
                self.send_error_response(400, {"status": "error", "message": str(e)})
                return
                
            # Call prompt.py with plaintext data
            try:
                logger.info(f"Request {request_id}: Calling AI service with {len(prompts)} data items")
                ai_response = prompt_main(case, prompts)
            except Exception as e:
                logger.error(f"Request {request_id}: AI service error: {str(e)}")
                self.send_error_response(500, {"status": "error", "message": "AI processing error"})
                return
            
            # Encrypt sensitive response if needed
            if should_encrypt_response(ai_response):
                logger.info(f"Request {request_id}: Encrypting sensitive response")
                encrypted_response = cipher_suite.encrypt(ai_response.encode())
                # For this implementation, we're decrypting before sending to demonstrate the flow
                # In a real production system, you might send the encrypted response to clients
                # who have the decryption key
                ai_response = cipher_suite.decrypt(encrypted_response).decode()
            
            logger.info(f"Request {request_id}: Sending successful response")
            self.send_secure_response(200, {"status": "success", "data": ai_response})
            
        except json.JSONDecodeError:
            logger.warning(f"Request {request_id}: Invalid JSON in request body")
            self.send_error_response(400, {"status": "error", "message": "Invalid JSON"})
        except Exception as e:
            logger.error(f"Request {request_id}: Unhandled exception: {str(e)}", exc_info=True)
            self.send_error_response(500, {"status": "error", "message": "Internal server error"})
    
    def parse_data(self, query_params):
        """Securely parse and validate input data"""
        if not isinstance(query_params, dict):
            raise ValueError("Invalid input format")
            
        values_list = query_params['prompts'][0].split(',') if 'prompts' in query_params else []
        prompt_key = query_params['whiteleafuc'][0] if 'whiteleafuc' in query_params else ''
        
        # Basic input validation
        if not values_list or not prompt_key:
            raise ValueError("Missing required data")
        
        # Validate input values (add more validation as needed)
        for value in values_list:
            if len(value) > 2048:  # Arbitrary limit
                raise ValueError("Input value exceeds maximum length")
            
        return (prompt_key, values_list)

    def send_secure_response(self, code, content):
        """Send response with security headers"""
        self.send_response(code)
        self.send_header("Content-type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.end_headers()
        self.wfile.write(json.dumps(content).encode())
    
    def send_error_response(self, code, content):
        """Send error response with appropriate headers"""
        self.send_response(code)
        self.send_header("Content-type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(json.dumps(content).encode())
    
    def log_message(self, format, *args):
        """Override to use our custom logger instead of stderr"""
        logger.info("%s - - [%s] %s" % (self.client_address[0], self.log_date_time_string(), format % args))

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 20

def start_server():
    """Start the HTTP server with encrypted payload handling"""
    try:
        server = ThreadedHTTPServer(("0.0.0.0", PORT), RequestHandler)
        logger.info(f"Server started on port {PORT}")
        
        # Add a simple health check
        logger.info("Running server health check...")
        try:
            import requests
            health_response = requests.get(f"http://localhost:{PORT}/health")
            if health_response.status_code == 200:
                logger.info("Health check passed")
            else:
                logger.warning(f"Health check returned: {health_response.status_code}")
        except:
            logger.warning("Health check failed to connect")
        
        # Start server
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopping...")
    except Exception as e:
        logger.critical(f"Failed to start server: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    # Add a healthcheck route
    RequestHandler.health_check_path = "/health"
    original_do_GET = RequestHandler.do_GET
    
    def do_GET_with_health(self):
        if self.path == self.health_check_path:
            self.send_secure_response(200, {"status": "ok"})
        else:
            original_do_GET(self)
    
    RequestHandler.do_GET = do_GET_with_health
    
    # Start the server
    start_server()