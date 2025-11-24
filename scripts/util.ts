import { join } from 'node:path'
import { homedir } from 'node:os'
import { IMasterSetup } from './types'
const setupFile = join(homedir(), '.master.json')
export const masterSetup: IMasterSetup = require(setupFile)

