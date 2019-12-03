const config = {
	"gatsby": {
		"pathPrefix": "/",
		"siteUrl": "https://akv4k8s.io",
		"gaTrackingId": null
	},
	"header": {
		"logo": "https://raw.githubusercontent.com/SparebankenVest/azure-key-vault-to-kubernetes/master/docs/images/akvk8s.png",
		"logoLink": "/",
		"title": "Azure Key Vault to Kubernetes",
		"githubUrl": "https://github.com/SparebankenVest/azure-key-vault-for-kubernetes",
		"helpUrl": "",
		"tweetText": "",
		"links": [
			{ "text": "", "link": ""}
		],
		"search": {
			"enabled": false,
			"indexName": "",
			"algoliaAppId": process.env.GATSBY_ALGOLIA_APP_ID,
			"algoliaSearchKey": process.env.GATSBY_ALGOLIA_SEARCH_KEY,
			"algoliaAdminKey": process.env.ALGOLIA_ADMIN_KEY
		}
	},
	"sidebar": {
		"forcedNavOrder": [
			"/index",
			"/setup",
			"/components",
			"/authentication",
			"/authorization",
			"/tasks",
			"/examples",
			"/reference",
			"/how-it-works"
		],
		"links": [
			{ "text": "Azure Key Vault to Kubernetes", "link": "https://github.com/SparebankenVest/azure-key-vault-to-kubernetes"},
		],
		"frontline": true,
		"ignoreIndex": false,
	},
	"siteMetadata": {
		"title": "Azure Key Vault to Kubernetes",
		"description": "Documentation for synchronizing or injecting secrets from Azure Key Vault to Kubernetes",
		"ogImage": null,
		"docsLocation": "https://github.com/SparebankenVest/akv4k8s-docs/tree/master/content/docs",
		"favicon": "https://raw.githubusercontent.com/SparebankenVest/azure-key-vault-to-kubernetes/master/docs/images/akvk8s.png"
	},
};

module.exports = config;