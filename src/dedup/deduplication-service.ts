import { AdvisoryRepository } from '../persistence/repositories/advisory-repository';
import { DeduplicationResult } from '../shared/types';
import logger from '../logging';

export class DeduplicationService {
  constructor(private advisoryRepo: AdvisoryRepository) {}

  async checkDuplication(
    sourceId: number,
    externalId: string,
    rawHash: string,
    cveIds: string[]
  ): Promise<DeduplicationResult> {
    // First check by source + external_id
    const result = await this.advisoryRepo.checkDuplication(sourceId, externalId, rawHash);

    if (!result.isNew) {
      logger.debug(
        { sourceId, externalId, isDifferent: result.isDifferent },
        'Advisory already exists'
      );
      return result;
    }

    // Check by CVE IDs
    if (cveIds.length > 0) {
      for (const cveId of cveIds) {
        const existingByCve = await this.advisoryRepo.findByCveId(cveId);
        if (existingByCve.length > 0) {
          // Found duplicate by CVE from different source
          logger.info(
            { sourceId, externalId, cveId, existingAdvisoryId: existingByCve[0].id },
            'Advisory found by CVE match (cross-source duplicate)'
          );
          
          // For MVP, we still treat this as new if from different source
          // But we log it for visibility
          return { isNew: true };
        }
      }
    }

    return { isNew: true };
  }
}
