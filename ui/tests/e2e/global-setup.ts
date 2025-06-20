import { FullConfig } from '@playwright/test';
import { execSync } from 'child_process';

async function globalSetup(config: FullConfig) {
  // Start Docker containers
  console.log('Starting Docker containers...');
  execSync('docker-compose -f ../docker-compose-dev.yml up -d api-dev postgres valkey worker-beat worker-dev', { stdio: 'inherit' });

  // Wait for services to be ready
  console.log('Waiting for services to be ready...');
  await new Promise(resolve => setTimeout(resolve, 30000)); // Wait 30 seconds for services to be ready

  // Register cleanup function
  process.on('exit', () => {
    console.log('Stopping Docker containers...');
    execSync('docker-compose -f ../docker-compose-dev.yml down', { stdio: 'inherit' });
  });
}

export default globalSetup;
