/**
 * @vitest-environment jsdom
 */

// src/components/__tests__/simple.test.tsx
import { describe, test, expect } from 'vitest'

describe('DOM Environment Test', () => {
  test('document should be available', () => {
    expect(document).toBeDefined()
    expect(document.body).toBeDefined()
  })

  test('can create elements', () => {
    const div = document.createElement('div')
    div.textContent = 'Hello World'
    expect(div.textContent).toBe('Hello World')
  })
})