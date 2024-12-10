# Scammer Information Crawler

A sophisticated web crawler designed to collect and analyze potentially fraudulent online activities, storing data in MongoDB for efficient analysis and retrieval.

## Features

- Intelligent domain analysis and risk scoring
- Multi-threaded crawling for improved performance
- Comprehensive data extraction (emails, phone numbers, crypto wallets, social media)
- Domain WHOIS and DNS information gathering
- Flexible MongoDB storage system
- Configurable crawling depth and patterns
- Built-in rate limiting and user agent rotation

## Prerequisites

- Python 3.8+
- MongoDB 4.4+
- PostgreSQL 12+ (optional, for hybrid storage)

## Installation

1. Clone the repository:
```bash

```

2. Create and activate a virtual environment:
```bash
# Create virtual environment
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on Unix/MacOS
source venv/bin/activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. Set up MongoDB:
```bash
# Start MongoDB service
# For Linux
sudo systemctl start mongod

# For macOS
brew services start mongodb-community

# For Windows (run as administrator)
net start MongoDB
```

## Configuration

1. Configure MongoDB connection in the crawler:
```python
mongo_config = {
    'uri': 'mongodb://localhost:27017/',
    'database': 'scam_intelligence'
}
```

2. Configure crawler settings:
```python
# Adjust in MongoIntelCrawler class initialization
crawler = MongoIntelCrawler(
    mongo_uri='mongodb://localhost:27017/',
    database='scam_intelligence'
)
```

## Usage

1. Basic usage with seed URLs:
```python
from crawler import MongoIntelCrawler

# Initialize crawler
crawler = MongoIntelCrawler(
    mongo_uri='mongodb://localhost:27017/',
    database='scam_intelligence'
)

# Define seed URLs
seed_urls = [
    'http://example1.com',
    'http://example2.com'
]

# Start crawling
crawler.start_crawling(seed_urls, max_workers=5)
```

2. Monitor crawling progress:
```bash
# Check crawler logs
tail -f crawler_YYYYMMDD.log
```

## Data Structure

### MongoDB Collections

1. `scam_data`:
```json
{
    "url": "string",
    "title": "string",
    "emails": ["string"],
    "phones": ["string"],
    "crypto_wallets": [
        {
            "type": "string",
            "address": "string"
        }
    ],
    "social_media": [
        {
            "platform": "string",
            "profile": "string"
        }
    ],
    "domain_info": "object",
    "timestamp": "date",
    "suspicious_score": "number"
}
```

2. `domains`:
```json
{
    "domain": "string",
    "registrar": "string",
    "creation_date": "date",
    "expiration_date": "date",
    "last_updated": "date",
    "status": "string",
    "name_servers": ["string"],
    "dns_records": {
        "A": ["string"],
        "MX": ["string"],
        "NS": ["string"],
        "TXT": ["string"]
    }
}
```

## Query Examples

1. Find high-risk domains:
```python
high_risk = scam_data.find({"suspicious_score": {"$gte": 2}})
```

2. Get recent crypto wallet addresses:
```python
recent_wallets = scam_data.find(
    {"crypto_wallets": {"$ne": []}},
    {"crypto_wallets": 1}
).sort("timestamp", -1)
```

## Maintenance

1. Database backup:
```bash
mongodump --db scam_intelligence --out /backup/path
```

2. Log rotation:
```bash
# Logs are automatically dated: crawler_YYYYMMDD.log
# Implement log rotation using logrotate or similar tool
```

## Security Considerations

- Use strong MongoDB authentication
- Implement IP rotation for crawling
- Respect robots.txt
- Store sensitive data securely
- Use rate limiting to avoid detection
- Regularly update patterns and detection rules

## Troubleshooting

Common issues and solutions:

1. Connection errors:
   - Verify MongoDB is running
   - Check firewall settings
   - Verify connection string

2. Crawling issues:
   - Check network connectivity
   - Verify user agent settings
   - Review rate limiting

3. Data extraction issues:
   - Update patterns
   - Check HTML parsing
   - Verify regex patterns

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to the branch
5. Create Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and research purposes only. Users are responsible for compliance with applicable laws and regulations.