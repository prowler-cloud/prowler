/** Display names a framework mapper may give a requirement.
 *  Dedicated mappers compose `id - name`, CIS/CCC/PCI use the bare `id` and the
 *  generic mapper (any framework without a dedicated one, including registry
 *  frameworks) uses the bare `name`, so extras maps register all of them. */
export const candidateRequirementNames = (
  id: string,
  name: string,
): string[] => {
  const candidates = [id];
  if (name) {
    candidates.push(name, `${id} - ${name}`);
  }
  return candidates;
};
