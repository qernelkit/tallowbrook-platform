// Our collections use string ids we choose ("shp_000123456", "dev_…") rather than
// ObjectIds, so documents are typed loosely at this boundary.

/**
 * @param {import('mongodb').Db} db
 * @param {string} name
 * @returns {import('mongodb').Collection<any>}
 */
export function collection(db, name) {
  return db.collection(name);
}
