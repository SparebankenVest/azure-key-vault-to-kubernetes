const ghpages = require('gh-pages')

// replace with your repo url
ghpages.publish(
  'public',
  {
    branch: 'gh-pages',
  },
  () => {
    console.log('Deploy Complete!')
  }
)