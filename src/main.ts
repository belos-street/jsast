#!/usr/bin/env bun

import { createCommand } from './cli'

const bootstrap = async () => {
  const program = createCommand(process)
}

bootstrap()
