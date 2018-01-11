<?php
namespace zongphp\rbac;

use zongphp\framework\build\Provider;

class RbacProvider extends Provider {
	//延迟加载
	public $defer = true;

	public function boot() {
	}

	public function register() {
		$this->app->single( 'Rbac', function () {
			return new Rbac();
		} );
	}
}
