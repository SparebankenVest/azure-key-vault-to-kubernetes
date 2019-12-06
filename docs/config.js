const config = {
	"gatsby": {
		"pathPrefix": "/",
		"siteUrl": "https://akv4k8s.io",
		"gaTrackingId": "UA-136446489-2"
	},
	"header": {
		"logo": "/images/akvk8s.png",
		"logoLink": "/",
		"title": "Azure Key Vault to Kubernetes",
		"githubUrl": "https://github.com/SparebankenVest/azure-key-vault-to-kubernetes",
		"helpUrl": "",
		"tweetText": "",
		"links": [
			{ "text": "", "link": ""}
		],
		"search": {
			"enabled": true,
			"indexName": "prod_akv2k8s",
			"algoliaAppId": process.env.GATSBY_ALGOLIA_APP_ID,
			"algoliaSearchKey": process.env.GATSBY_ALGOLIA_SEARCH_KEY,
			"algoliaAdminKey": process.env.ALGOLIA_ADMIN_KEY
		}
	},
	"sidebar": {
		"forcedNavOrder": [
			"/index",
			"/installation",
			"/components",
			"/authentication",
			"/authorization",
			"/tutorials",
			"/examples",
			"/reference",
			"/how-it-works"
		],
		"links": [
		],
		"frontline": true,
		"ignoreIndex": false,
	},
	"siteMetadata": {
		"title": "Azure Key Vault to Kubernetes",
		"description": "Documentation for synchronizing or injecting secrets from Azure Key Vault to Kubernetes",
		"ogImage": null,
		"docsLocation": "https://github.com/SparebankenVest/azure-key-vault-to-kubernetes/tree/master/docs/content",
		"favicon": "/images/akvk8s.png"
	},
};

module.exports = config;