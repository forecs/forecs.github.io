import DefaultTheme from 'vitepress/theme'
import ApprovedArticle from './components/ApprovedArticle.vue'
import ArticleIndex from './components/ArticleIndex.vue'
import HomeOverview from './components/HomeOverview.vue'
import './style.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('ApprovedArticle', ApprovedArticle)
    app.component('ArticleIndex', ArticleIndex)
    app.component('HomeOverview', HomeOverview)
  }
}
