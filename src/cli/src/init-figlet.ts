import figlet from 'figlet'
import Isometric1 from 'figlet/importable-fonts/Isometric1.js'

figlet.parseFont('Isometric1', Isometric1)

export const initFiglet = (text: string): string => {
  const figletText = figlet.textSync(text, {
    font: 'Isometric1',
    horizontalLayout: 'default',
    verticalLayout: 'default'
  })
  return figletText + '\n'
}
