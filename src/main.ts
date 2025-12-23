#!/usr/bin/env bun

import { createCommand } from './cli'
import { processRules } from './parse'

const bootstrap = async () => {
  const { options } = createCommand(process)

  const rules = processRules(options)
  console.log(rules)
}

bootstrap()
