import { SourceConnector } from './base/connector';
import { CisaKevConnector } from './cisa-kev/cisa-kev-connector';
import { OsvConnector } from './osv/osv-connector';

export function getConnectors(): SourceConnector[] {
  return [
    new CisaKevConnector(),
    new OsvConnector(),
  ];
}

export function getConnectorByName(name: string): SourceConnector | null {
  const connectors = getConnectors();
  return connectors.find(c => c.name === name) || null;
}
