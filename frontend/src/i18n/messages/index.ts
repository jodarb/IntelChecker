// Every area file exports { en, es } with `es` typed against `en`, so a missing or
// misspelled Spanish key is a compile error. Add new areas to both spreads below.
import common from './common'
import layout from './layout'
import home from './home'
import results from './results'
import summary from './summary'
import verdict from './verdict'
import history from './history'
import admin from './admin'
import cards from './cards'
import auth from './auth'
import connectors from './connectors'
import company from './company'

export const messages = {
  en: {
    ...common.en, ...layout.en, ...home.en, ...results.en, ...summary.en,
    ...verdict.en, ...history.en, ...admin.en, ...cards.en, ...auth.en, ...connectors.en, ...company.en
  },
  es: {
    ...common.es, ...layout.es, ...home.es, ...results.es, ...summary.es,
    ...verdict.es, ...history.es, ...admin.es, ...cards.es, ...auth.es, ...connectors.es, ...company.es
  },
}
