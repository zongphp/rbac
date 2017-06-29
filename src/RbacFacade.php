<?php
namespace zongphp\rbac;

use zongphp\framework\build\Facade;

class RbacFacade extends Facade {
	public static function getFacadeAccessor() {
		return 'Rbac';
	}
}