from crawler import ScammerIntelCrawler
import logging
import time

def main():
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # MongoDB configuration
    mongo_config = {
        'uri': 'mongodb+srv://devscamai:<password>@scamdb.cmpqi.mongodb.net/',
        'database': 'scamdb'
    }
    
    # Initialize crawler
    crawler = ScammerIntelCrawler(
        mongo_uri=mongo_config['uri'],
        database=mongo_config['database']
    )
    
    # Add your seed URLs
    seed_urls = [
        'https://www.reddit.com/r/Scams/'  # Replace with actual URLs

    ]
    
    print("Starting crawler...")
    try:
        # Test MongoDB connection
        crawler.db.command('ping')
        logging.info("MongoDB connection successful")
        
        # Test each URL before crawling
        for url in seed_urls:
            try:
                logging.info(f"Testing connection to {url}")
                response = crawler.crawl_url(url, depth=0, max_depth=1)
                logging.info(f"Successfully connected to {url}")
                # Add small delay between requests
                time.sleep(2)
            except Exception as e:
                logging.error(f"Error testing {url}: {str(e)}")
        
        # Start the actual crawling
        crawler.start_crawling(seed_urls, max_workers=2)
        print("Crawling completed!")
        
        # Check results
        count = crawler.scammers.count_documents({})
        print(f"Total documents collected: {count}")
        
    except Exception as e:
        print(f"Error during crawling: {str(e)}")
        logging.error(f"Critical error: {str(e)}")

if __name__ == "__main__":
    main()