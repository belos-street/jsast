#!/usr/bin/env bun

import { createCommand } from './cli'

const bootstrap = async () => {
  const { options } = createCommand(process)
  console.log(options)
}

bootstrap()
