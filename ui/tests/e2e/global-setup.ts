import { FullConfig } from '@playwright/test';
import { execSync } from 'child_process';

async function globalSetup(config: FullConfig) {
  const isLocal = process.env.LOCAL === 'true';

  if (isLocal) {
    console.log('LOCAL=true detected — skipping Docker startup.');
    return;
  }

  // Start Docker containers (for CI or non-local runs)
  console.log('Starting Docker containers...');
  execSync(
    'docker-compose -f ../docker-compose-dev.yml up -d --build api-dev postgres valkey worker-beat worker-dev',
    { stdio: 'inherit' }
  );

  // Wait for services to be ready
  console.log('Waiting for services to be ready...');
  await new Promise((resolve) => setTimeout(resolve, 30000)); // Wait 30 seconds

  // Register cleanup function
  process.on('exit', () => {
    console.log('Cleaning up containers...');
    execSync('docker-compose -f ../docker-compose-dev.yml down', { stdio: 'inherit' });
  });
}

export default globalSetup;
