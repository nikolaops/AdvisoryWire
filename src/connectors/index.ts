import { SourceConnector } from './base/connector';
import { GithubAdvisoryConnector } from './github-advisory/github-advisory-connector';
import { OsvConnector } from './osv/osv-connector';

export function getConnectors(): SourceConnector[] {
  return [
    new GithubAdvisoryConnector(),
    new OsvConnector(),
  ];
}

export function getConnectorByName(name: string): SourceConnector | null {
  const connectors = getConnectors();
  return connectors.find(c => c.name === name) || null;
}
