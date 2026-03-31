import { SourceFetchResult } from '../../shared/types';

export interface SourceConnector {
  readonly name: string;
  readonly type: string;
  
  fetch(sinceDate?: Date): Promise<SourceFetchResult>;
}

export abstract class BaseConnector implements SourceConnector {
  abstract readonly name: string;
  abstract readonly type: string;

  abstract fetch(sinceDate?: Date): Promise<SourceFetchResult>;

  protected handleError(error: any): SourceFetchResult {
    const message = error?.message || String(error);
    return {
      success: false,
      items: [],
      errorMessage: message,
    };
  }
}
