# WPCLI Patchstack Integration
Identify WordPress core, plugin and theme vulnerabilities with WP CLI.

### Features

`wp patchstack --help`
- Return all the commands of the package.

`wp patchstack validate --api=`
- Run this first to validate your API key and use the package further

`wp patchstack scan`
- Run this scan your WordPress installation. It returns only the plugins who need to get patched.

`wp patchstack scan --all`
- Run this scan your WordPress installation. It returns all the pugins listed on the WordPress Installation.


### Links

[Patchstack](https://patchstack.com/)

[Patchstack API Documentation](https://www.notion.so/Database-API-Documentation-96dd848b35474ec28a5aba7bbf2b5c1f)

### Contributors
- Patchstack Team (https://patchstack.com/) - Providing the API and Development Resources
- Cloudways Team (https://cloudways.com/) - Providing the WP-CLI Integration & Comunity Resources
