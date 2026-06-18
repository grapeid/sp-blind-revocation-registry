export function anchoringEnabled(): boolean {
  return process.env.BRR_ANCHORING_ENABLED === 'true';
}