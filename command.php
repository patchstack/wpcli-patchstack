
<?php

if (!class_exists('WP_CLI')) {
	return;
}

class patchstack_CLI {

	private $apiBaseUrl = 'https://patchstack.com/database/api/v2';

	/**
	 * Validates patchstack API [--api=<key>]
	 *
	 */
	public function validate($args, $assoc_args) {

		$a = $assoc_args['api'];
		// --api
		if ($assoc_args['api']) {
			list($response, $code) = $this->sendRequest($this->apiBaseUrl, '/latest', $assoc_args['api']);
			if ($code != 200) {
				WP_CLI::error('Invalid API Key', true);
			} else {

				WP_CLI::success('API Key is valid');
				$options = array(
					'return' => true,
					'parse' => 'json',
					'launch' => false,
					'exit_error' => true,
				);
				WP_CLI::runCommand('transient delete PATCH_API_KEY', $options);
				WP_CLI::runCommand('transient set PATCH_API_KEY ' . $a, $options);

			}

		}
	}

	/**
	 * scans all plugins for vulnurebilities
	 *
	 */

	public function scan($args, $assoc_args) {

		$apikey = WP_CLI::runCommand('transient get PATCH_API_KEY', array('return' => true, 'launch' => true, 'exit_error' => false));

		if (!$apikey) {
			WP_CLI::error('API Key not provided. Please use validate command and provide API Key', true);
		}

		$options = array(
			'return' => true, // Return 'STDOUT'; use 'all' for full object.
			'parse' => 'json', // Parse captured STDOUT to JSON array.
			'launch' => false, // Reuse the current process.
			'exit_error' => true, // Halt script execution on error.
		);
		$plugins = WP_CLI::runcommand('plugin list --status=active --fields=title,description,name,version --format=json', $options);
		if ($plugins) {
			$body = [];
			foreach ($plugins as $plugin) {
				$body[] = ["name" => urlencode($plugin['name']), "version" => $plugin['version'], 'title' => urlencode($plugin['title']), 'description' => urlencode($plugin['description']), "type" => "plugin", "exists" => false];
			}
		}

		list($response, $code) = $this->sendRequest($this->apiBaseUrl, '/batch', $apikey, 'POST', $body);
		if ($code == 200) {
			$response = json_decode($response, true);
			$this->formatter($args, $assoc_args, $response, $body);
		} else if ($code == 403) {
			WP_CLI::error('Invalid API Key', true);
		} else {
			WP_CLI::error('Error occured code:' . $code, true);
		}

	}

	private function sendRequest($baseUrl, $path, $apiKey, $type = 'GET', $array = []) {
		if ($type == 'GET') {
			$ch = curl_init();
			$headers = array(
				'PSKey: ' . $apiKey,
				'content-type: application/json',
			);
			curl_setopt($ch, CURLOPT_URL, $baseUrl . $path);
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
			curl_setopt($ch, CURLOPT_HEADER, 0);

			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

			$response = curl_exec($ch);
			$httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
			curl_close($ch);
			return [$response, $httpcode];
		} else {
			$ch = curl_init();
			$headers = array(
				'PSKey: ' . $apiKey,
				'content-type: application/json',
			);

			$post = $array;

			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post));

			curl_setopt($ch, CURLOPT_URL, $baseUrl . $path);
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
			curl_setopt($ch, CURLOPT_HEADER, 0);

			$response = curl_exec($ch);
			$httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
			curl_close($ch);
			return [$response, $httpcode];
		}

	}

	private function formatter($args, $assoc_args, $data, $orgBody) {

		$list = [];
		$vExist = [];
		if ($data['vulnerabilities']) {
			$count = 0;
			foreach ($data['vulnerabilities'] as $vs) {

				foreach ($vs as $v) {
					$vExist[] = $v['product_slug'];
					$list[] = array(
						'plugin_name' => $v['product_name'],
						'version' => $orgBody[$count]['version'],
						'vulnerability' => 'True',
						'affected_in' => $v['affected_in'],
						'fixed_in' => $v['fixed_in'],
						'title' => $v['title'],
						'description' => $v['description'],
					);
				}
				$count += 1;
			}
		}
		if ($assoc_args['all']) {
			foreach ($orgBody as $org) {
				if (!in_array($org['name'], $vExist)) {
					$list[] = array(
						'plugin_name' => $org['title'],
						'version' => $org['version'],
						'vulnerability' => 'False',
						'affected_in' => '-',
						'fixed_in' => '-',
						'title' => '-',
						'description' => '-',
					);
				}
			}
		}

		$formatter = new \WP_CLI\Formatter($assoc_args, array(
			'plugin_name',
			'version',
			'vulnerability',
			'affected_in',
			'fixed_in',
			'title',
			'description',
		));

		$formatter->display_items(($list));
	}

}

WP_CLI::add_command('patchstack', 'patchstack_CLI');
