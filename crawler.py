import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime
import pymongo
from typing import Dict, List, Any
import logging
from fake_useragent import UserAgent
import whois
import dns.resolver
from urllib.parse import urljoin, urlparse
import time
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import ssl

# Suppress SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)

class ScammerIntelCrawler:
    def __init__(self, mongo_uri: str, database: str):
        # Initialize MongoDB connection
        self.client = pymongo.MongoClient(mongo_uri)
        self.db = self.client[database]
        self.scammers = self.db.scammers
        self.ua = UserAgent()
        self.visited_urls = set()
        
        # Configure session with retry strategy and older TLS support
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        # Create custom adapter with older TLS support
        class OldTLSAdapter(HTTPAdapter):
            def init_poolmanager(self, *args, **kwargs):
                context = urllib3.util.ssl_.create_urllib3_context(
                    ciphers='DEFAULT:!DH',
                    ssl_version=ssl.PROTOCOL_TLSv1_2
                )
                kwargs['ssl_context'] = context
                return super().init_poolmanager(*args, **kwargs)

        # Configure adapters with older TLS support
        adapter = OldTLSAdapter(max_retries=retry_strategy)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
        self.session.verify = False
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=f'scam_crawler_{datetime.now().strftime("%Y%m%d")}.log'
        )
        
        # Updated patterns for data extraction
        self.patterns = {
            'phone': r'''(?x)
                (?:
                    # Format: +1 (234) 567-8901
                    (?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}|
                    
                    # Format: +1-234-567-8901
                    (?:\+\d{1,3}[\s-]?)?\d{3}[-\s]?\d{3}[-\s]?\d{4}|
                    
                    # Format: 1.234.567.8901
                    (?:\+?\d{1,3}[\.]?)?\d{3}[\.]\d{3}[\.]\d{4}|
                    
                    # Format: +12345678901
                    (?:\+?\d{1,3})\d{10}
                )
            ''',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'crypto': {
                'BTC': r'bc1[a-zA-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}',
                'ETH': r'0x[a-fA-F0-9]{40}',
                'XRP': r'r[0-9a-zA-Z]{24,34}',
                'LTC': r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}'
            },
            'social_media': {
                'telegram': r't\.me/[\w]+',
                'twitter': r'twitter\.com/[\w]+',
                'facebook': r'facebook\.com/[\w\.]+',
                'instagram': r'instagram\.com/[\w\.]+',
                'whatsapp': r'wa\.me/[\d]+',
                'discord': r'discord\.gg/[\w]+|discordapp\.com/users/[\d]+'
            }
        }

    def standardize_phone_number(self, phone: str) -> str:
        """Standardize phone number format"""
        # Remove all non-digit characters
        digits = re.sub(r'\D', '', phone)
        
        # Handle international format
        if len(digits) > 10:
            return f"+{digits}"
        # Handle domestic format
        elif len(digits) == 10:
            return f"+1{digits}"
        return digits

    def get_domain_info(self, url: str) -> Dict:
        try:
            domain = urlparse(url).netloc
            w = whois.whois(domain)
            
            dns_info = {
                'A': [],
                'MX': [],
                'NS': [],
                'TXT': []
            }
            
            for record_type in dns_info.keys():
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_info[record_type] = [str(answer) for answer in answers]
                except Exception:
                    continue
                    
            return {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'dns_records': dns_info
            }
        except Exception as e:
            logging.error(f"Error getting domain info for {url}: {str(e)}")
            return {}

    def calculate_risk_score(self, data: Dict) -> int:
        score = 5  # Base score
        
        if data.get('domain_info', {}).get('creation_date'):
            creation_date = data['domain_info']['creation_date']
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            domain_age = (datetime.now() - creation_date).days
            if domain_age < 30:
                score += 2
            elif domain_age < 90:
                score += 1
                
        if len(data.get('identifiers', {}).get('phones', [])) > 2:
            score += 1
        if len(data.get('identifiers', {}).get('emails', [])) > 2:
            score += 1
            
        if data.get('identifiers', {}).get('cryptoWallets', []):
            score += 1
            
        suspicious_terms = ['wallet', 'crypto', 'invest', 'binary', 'forex', 'profit']
        if any(term in str(data.get('onlinePresence', {}).get('websites', [])).lower() 
               for term in suspicious_terms):
            score += 1
            
        return min(score, 10)

    def extract_information(self, url: str, html_content: str) -> Dict:
        soup = BeautifulSoup(html_content, 'html.parser')
        current_time = datetime.now()
        
        extracted_data = {
            'dateAdded': current_time,
            'lastUpdated': current_time,
            'status': 'under_investigation',
            'identifiers': {
                'phones': [],
                'emails': [],
                'cryptoWallets': []
            },
            'onlinePresence': {
                'websites': [{
                    'url': url,
                    'domain': urlparse(url).netloc,
                    'status': 'active',
                    'firstSeen': current_time,
                    'lastSeen': current_time
                }],
                'socialMedia': []
            }
        }
        
        text_content = soup.get_text()
        full_content = f"{html_content} {text_content}"
        
        phones = set(re.findall(self.patterns['phone'], full_content, re.VERBOSE))
        for phone in phones:
            standardized_phone = self.standardize_phone_number(phone)
            extracted_data['identifiers']['phones'].append({
                'number': standardized_phone,
                'originalFormat': phone,
                'firstSeen': current_time,
                'lastSeen': current_time,
                'status': 'active'
            })
            
        emails = set(re.findall(self.patterns['email'], full_content))
        for email in emails:
            extracted_data['identifiers']['emails'].append({
                'address': email.lower(),
                'domain': email.split('@')[1].lower(),
                'firstSeen': current_time,
                'lastSeen': current_time,
                'status': 'active'
            })
            
        for crypto_type, pattern in self.patterns['crypto'].items():
            wallets = set(re.findall(pattern, full_content))
            for wallet in wallets:
                extracted_data['identifiers']['cryptoWallets'].append({
                    'address': wallet,
                    'type': crypto_type,
                    'firstSeen': current_time,
                    'lastSeen': current_time
                })
                
        for platform, pattern in self.patterns['social_media'].items():
            profiles = set(re.findall(pattern, full_content))
            for profile in profiles:
                extracted_data['onlinePresence']['socialMedia'].append({
                    'platform': platform,
                    'username': profile.split('/')[-1],
                    'profileUrl': profile,
                    'status': 'active',
                    'firstSeen': current_time,
                    'lastSeen': current_time
                })
                
        return extracted_data

    def store_data(self, data: Dict) -> None:
        try:
            domain_info = self.get_domain_info(data['onlinePresence']['websites'][0]['url'])
            if domain_info:
                data['domain_info'] = domain_info
                
            data['riskScore'] = self.calculate_risk_score(data)
            
            self.scammers.update_one(
                {
                    'onlinePresence.websites.domain': data['onlinePresence']['websites'][0]['domain']
                },
                {'$set': data},
                upsert=True
            )
            
            logging.info(f"Stored data for domain: {data['onlinePresence']['websites'][0]['domain']}")
            
        except Exception as e:
            logging.error(f"Error storing data: {str(e)}")

    def crawl_url(self, url: str, depth: int = 0, max_depth: int = 3) -> None:
        if depth > max_depth or url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        
        try:
            headers = {
                'User-Agent': self.ua.random,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0'
            }
            
            # Add delay between requests
            time.sleep(2)
            
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            extracted_data = self.extract_information(url, response.text)
            if any(len(v) > 0 for v in [
                extracted_data['identifiers']['phones'],
                extracted_data['identifiers']['emails'],
                extracted_data['identifiers']['cryptoWallets']
            ]):
                self.store_data(extracted_data)
                
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            
            for link in links:
                next_url = urljoin(url, link['href'])
                if next_url.startswith('http'):
                    self.crawl_url(next_url, depth + 1, max_depth)
                    
        except Exception as e:
            logging.error(f"Error crawling {url}: {str(e)}")

    def start_crawling(self, seed_urls: List[str], max_workers: int = 5) -> None:
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                executor.map(self.crawl_url, seed_urls)
                
        except Exception as e:
            logging.error(f"Error in crawling process: {str(e)}")