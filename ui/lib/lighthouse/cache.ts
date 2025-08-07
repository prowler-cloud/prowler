import Valkey from "iovalkey";

import { auth } from "@/auth.config";

import {
  generateBannerFromDetailed,
  generateDetailedRecommendation,
  generateQuestionAnswers,
} from "./recommendations";
import { suggestedActions } from "./suggested-actions";
import {
  compareProcessedScanIds,
  generateSecurityScanSummary,
  getCompletedScansLast24h,
} from "./summary";

let valkeyClient: Valkey | null = null;

export async function getValkeyClient(): Promise<Valkey> {
  if (!valkeyClient) {
    valkeyClient = new Valkey({
      host: process.env.VALKEY_HOST,
      port: parseInt(process.env.VALKEY_PORT || "6379"),
      connectTimeout: 5000,
      lazyConnect: true,
    });
  }

  return valkeyClient;
}

export class CacheService {
  private static async getTenantId(): Promise<string | null> {
    const session = await auth();
    return session?.tenantId || null;
  }

  private static async acquireProcessingLock(
    tenantId: string,
    lockKey: string,
    lockTtlSeconds: number = 300,
  ): Promise<boolean> {
    try {
      const client = await getValkeyClient();
      const fullLockKey = `_lighthouse:${tenantId}:lock:${lockKey}`;

      const result = await client.set(
        fullLockKey,
        Date.now().toString(),
        "EX",
        lockTtlSeconds,
        "NX",
      );

      return result === "OK";
    } catch (error) {
      return false;
    }
  }

  private static async releaseProcessingLock(
    tenantId: string,
    lockKey: string,
  ): Promise<void> {
    try {
      const client = await getValkeyClient();
      const fullLockKey = `_lighthouse:${tenantId}:lock:${lockKey}`;
      await client.del([fullLockKey]);
    } catch (error) {
      // Silent failure
    }
  }

  static async getProcessedScanIds(): Promise<string[]> {
    const tenantId = await this.getTenantId();
    if (!tenantId) return [];

    try {
      const client = await getValkeyClient();
      const dataKey = `_lighthouse:${tenantId}:processed_scan_ids`;

      const result = await client.get(dataKey);
      if (!result) return [];

      const scanIdsString = result.toString();
      return scanIdsString ? scanIdsString.split(",") : [];
    } catch (error) {
      return [];
    }
  }

  static async setProcessedScanIds(scanIds: string[]): Promise<boolean> {
    const tenantId = await this.getTenantId();
    if (!tenantId) return false;

    try {
      const client = await getValkeyClient();
      const dataKey = `_lighthouse:${tenantId}:processed_scan_ids`;
      const scanIdsString = scanIds.join(",");

      await client.set(dataKey, scanIdsString);
      return true;
    } catch (error) {
      return false;
    }
  }

  static async processScansWithLock(scanIds: string[]): Promise<{
    success: boolean;
    data?: string;
  }> {
    const tenantId = await this.getTenantId();
    if (!tenantId) return { success: false };

    const lockKey = "scan-processing";
    const lockTtlSeconds = 1200; // 20 minutes

    try {
      // Try to acquire processing lock
      const lockAcquired = await this.acquireProcessingLock(
        tenantId,
        lockKey,
        lockTtlSeconds,
      );

      if (!lockAcquired) {
        // Processing is happening in background, return success but no data
        return { success: true };
      }

      try {
        // Generate the scan summary for the provided scan IDs
        const scanSummary = await generateSecurityScanSummary(scanIds);

        // Only process if we have valid scan summary
        if (scanSummary) {
          // Cache the scan summary
          await this.set("scan-summary", scanSummary);

          // Mark scans as processed
          await this.setProcessedScanIds(scanIds);

          // Generate and cache recommendations asynchronously
          this.generateAndCacheRecommendations(scanSummary).catch((error) => {
            console.error(
              "Background recommendation generation failed:",
              error,
            );
          });

          return {
            success: true,
            data: scanSummary,
          };
        } else {
          // Even if no summary, mark scans as processed to avoid reprocessing
          await this.setProcessedScanIds(scanIds);
        }

        return { success: true };
      } finally {
        await this.releaseProcessingLock(tenantId, lockKey);
      }
    } catch (error) {
      console.error("Error processing scans with lock:", error);
      return { success: false };
    }
  }

  // Generic cache methods for future use
  static async get(key: string): Promise<string | null> {
    const tenantId = await this.getTenantId();
    if (!tenantId) return null;

    try {
      const client = await getValkeyClient();
      const fullKey = `_lighthouse:${tenantId}:${key}`;
      const result = await client.get(fullKey);
      return result?.toString() || null;
    } catch (error) {
      return null;
    }
  }

  static async set(
    key: string,
    value: string,
    ttlSeconds?: number,
  ): Promise<boolean> {
    const tenantId = await this.getTenantId();
    if (!tenantId) return false;

    try {
      const client = await getValkeyClient();
      const fullKey = `_lighthouse:${tenantId}:${key}`;

      if (ttlSeconds) {
        await client.set(fullKey, value, "EX", ttlSeconds);
      } else {
        await client.set(fullKey, value);
      }

      return true;
    } catch (error) {
      return false;
    }
  }

  static async getRecommendations(): Promise<{
    success: boolean;
    data?: string;
  }> {
    const tenantId = await this.getTenantId();
    if (!tenantId) return { success: false };

    try {
      const client = await getValkeyClient();
      const dataKey = `_lighthouse:${tenantId}:recommendations`;

      const cachedData = await client.get(dataKey);
      if (cachedData) {
        return {
          success: true,
          data: cachedData.toString(),
        };
      }

      return { success: true, data: undefined };
    } catch (error) {
      return { success: false };
    }
  }

  static async generateAndCacheRecommendations(scanSummary: string): Promise<{
    success: boolean;
    data?: string;
  }> {
    const tenantId = await this.getTenantId();
    if (!tenantId) return { success: false };

    const lockKey = "recommendations-processing";
    const dataKey = `_lighthouse:${tenantId}:recommendations`;
    const detailedDataKey = `_lighthouse:${tenantId}:cached-messages:recommendation`;

    try {
      const client = await getValkeyClient();

      // Check if data already exists
      const existingData = await client.get(dataKey);
      if (existingData) {
        return {
          success: true,
          data: existingData.toString(),
        };
      }

      // Lock TTL 10 minutes
      const lockAcquired = await this.acquireProcessingLock(
        tenantId,
        lockKey,
        600,
      );

      if (!lockAcquired) {
        // Processing is happening in background, return success but no data
        return { success: true };
      }

      try {
        // Double-check after acquiring lock
        const doubleCheckData = await client.get(dataKey);
        if (doubleCheckData) {
          return {
            success: true,
            data: doubleCheckData.toString(),
          };
        }

        // Generate detailed recommendation first
        const detailedRecommendation =
          await generateDetailedRecommendation(scanSummary);

        if (!detailedRecommendation.trim()) {
          return { success: true, data: "" };
        }

        // Generate banner from detailed content
        const bannerRecommendation = await generateBannerFromDetailed(
          detailedRecommendation,
        );

        // Both must succeed - no point in detailed without banner
        if (!bannerRecommendation.trim()) {
          return { success: true, data: "" };
        }

        // Generate question answers
        const questionAnswers = await generateQuestionAnswers(suggestedActions);

        // Cache both versions
        await client.set(dataKey, bannerRecommendation);
        await client.set(detailedDataKey, detailedRecommendation);

        // Cache question answers with 24h TTL
        for (const [questionRef, answer] of Object.entries(questionAnswers)) {
          const questionKey = `_lighthouse:${tenantId}:cached-messages:question_${questionRef}`;
          await client.set(questionKey, answer, "EX", 86400); // 24 hours
        }

        return {
          success: true,
          data: bannerRecommendation,
        };
      } finally {
        await this.releaseProcessingLock(tenantId, lockKey);
      }
    } catch (error) {
      console.error("Error generating and caching recommendations:", error);
      return { success: false };
    }
  }

  static async isRecommendationProcessing(): Promise<boolean> {
    const tenantId = await this.getTenantId();
    if (!tenantId) return false;

    try {
      const client = await getValkeyClient();
      const lockKey = `_lighthouse:${tenantId}:lock:recommendations-processing`;

      const result = await client.get(lockKey);
      return result !== null;
    } catch (error) {
      return false;
    }
  }

  // New method to get cached message by type
  static async getCachedMessage(messageType: string): Promise<{
    success: boolean;
    data?: string;
  }> {
    const tenantId = await this.getTenantId();
    if (!tenantId) return { success: false };

    try {
      const client = await getValkeyClient();
      const dataKey = `_lighthouse:${tenantId}:cached-messages:${messageType}`;

      const cachedData = await client.get(dataKey);
      if (cachedData) {
        return {
          success: true,
          data: cachedData.toString(),
        };
      }

      return { success: true, data: undefined };
    } catch (error) {
      console.error(`Error getting cached message ${messageType}:`, error);
      return { success: false };
    }
  }

  // New method to set cached message by type
  static async setCachedMessage(
    messageType: string,
    content: string,
  ): Promise<boolean> {
    const tenantId = await this.getTenantId();
    if (!tenantId) return false;

    try {
      const client = await getValkeyClient();
      const dataKey = `_lighthouse:${tenantId}:cached-messages:${messageType}`;
      await client.set(dataKey, content);
      return true;
    } catch (error) {
      console.error(`Error caching message type ${messageType}:`, error);
      return false;
    }
  }
}

export async function initializeTenantCache(): Promise<{
  success: boolean;
  data?: string;
  scanSummary?: string;
}> {
  try {
    // Check if there are any scans in the last 24h
    const currentScanIds = await getCompletedScansLast24h();

    if (currentScanIds.length === 0) {
      // No scans in last 24h, return existing cached data if any
      const existingSummary = await CacheService.get("scan-summary");
      return {
        success: true,
        data: existingSummary || undefined,
        scanSummary: existingSummary || undefined,
      };
    }

    // Check if we need to process these scans
    const processedScanIds = await CacheService.getProcessedScanIds();
    const shouldProcess = !compareProcessedScanIds(
      currentScanIds,
      processedScanIds,
    );

    if (!shouldProcess) {
      // Scans already processed, return existing cached data
      const existingSummary = await CacheService.get("scan-summary");
      return {
        success: true,
        data: existingSummary || undefined,
        scanSummary: existingSummary || undefined,
      };
    }

    // New scans found, trigger full processing with lock
    const result = await CacheService.processScansWithLock(currentScanIds);
    return {
      success: result.success,
      data: result.data,
      scanSummary: result.data,
    };
  } catch (error) {
    console.error("Error initializing tenant cache:", error);
    return {
      success: false,
    };
  }
}
