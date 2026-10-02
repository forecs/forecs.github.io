import publicData from '../public-data.json'
import { validatePublicData } from '../shared.mjs'

// A JSON module, not generated JavaScript or an article-derived template.
export const { articles, legacy, downloads } = validatePublicData(publicData)
