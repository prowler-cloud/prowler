Database migrations now give up after a few seconds when another query holds the table lock, instead of stalling every request that touches that table
