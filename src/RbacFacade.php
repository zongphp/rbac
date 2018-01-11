<?php
namespace zongphp\facade;

use zongphp\framework\build\Facade;

class RbacFacade extends Facade {
	public static function getFacadeAccessor() {
		return 'Rbac';
	}
}
