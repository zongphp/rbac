<?php
namespace zongphp\rbac\build;

use zongphp\config\Config;
use zongphp\session\Session;

class Base {
	protected $user_table;
	protected $role_table;
	protected $node_table;
	protected $user_role_table;
	protected $access_table;
	protected $auth_key;

	public function __construct( $facade ) {
		$this->facade          = $facade;
		$this->user_table      = Config::get( 'database.prefix' ) . Config::get( 'rbac.user_table' );
		$this->role_table      = Config::get( 'database.prefix' ) . Config::get( 'rbac.role_table' );
		$this->node_table      = Config::get( 'database.prefix' ) . Config::get( 'rbac.node_table' );
		$this->user_role_table = Config::get( 'database.prefix' ) . Config::get( 'rbac.user_role_table' );
		$this->access_table    = Config::get( 'database.prefix' ) . Config::get( 'rbac.access_table' );
		$this->auth_key        = Config::get( 'rbac.auth_key' );
	}

	/**
	 * 获取用户所有角色名称
	 *
	 * @param $id 会员id
	 *
	 * @return array
	 */
	public function getRoleName( $id ) {
		$sql = "SELECT * FROM " . $this->user_role_table . " u " .
		       " JOIN " . $this->role_table . " r ON ur.role_id = r.id " .
		       " WHERE ur.user_id=" . $id;
		if ( $data = Db::select( $sql ) ) {
			foreach ( $data as $d ) {
				$r[] = $d['name'];
			}

			return $r;
		}
	}

	/**
	 * 获取所有节点
	 *
	 * @return array
	 */
	public function getLevelNode() {
		$sql = "SELECT * FROM " . $this->node_table . " n ORDER BY n.sort ASC ";

		$data = Db::select( $sql );
		if ( ! $data ) {
			return [ ];
		}

		return $this->formatNode( $data );
	}

	/**
	 * 验证提供的"模块.控制器.动作"
	 *
	 * @param  string $action 模块.控制器.动作
	 *
	 * @return bool
	 */
	public function authAction( $action ) {
		$info = explode( '.', $action );
		//权限检查
		foreach ( Session::get( '__RBAC__' ) as $app => $a ) {
			if ( $app == strtolower( $info[0] ) ) {
				if ( isset( $a['_NODE_'][ strtolower( $info[1] ) ] ) ) {
					if ( isset( $a['_NODE_'][ strtolower( $info[1] ) ]['_NODE_'][ strtolower( $info[2] ) ] ) ) {
						if ( isset( $a['_NODE_'][ strtolower( $info[1] ) ]['_NODE_'][ strtolower( $info[2] ) ]['_NODE_'][ strtolower( $info[3] ) ] ) ) {
							return true;
						}
					}
				}
			}
		}

		return false;
	}

	/**
	 * 获取用户的所有权限节点
	 *
	 * @param int $uid 会员编号
	 *
	 * @return array
	 */
	public function getUserNode( $uid ) {
		$sql = "SELECT n.id,n.name,n.pid,n.level,n.title,n.show FROM " .
		       $this->user_role_table . " ur" . " JOIN " . $this->role_table .
		       " r ON ur.role_id = r.id " . " JOIN " . $this->access_table .
		       " a ON a.role_id=r.id " . " JOIN " . $this->node_table .
		       " n ON n.id = a.node_id" . " WHERE ur.user_id=" . $uid .
		       " AND n.status=1 AND r.status=1" . " GROUP BY a.node_id" .
		       " ORDER BY n.sort ASC";

		$data = Db::select( $sql );
		if ( ! $data ) {
			return [ ];
		}

		return $this->formatNode( $data );
	}

	/**
	 * 登录检测
	 */
	public function isLogin() {
		return Session::get( $this->auth_key );
	}

	/**
	 * 验证权限
	 * @return bool
	 */
	public function verify() {
		//检查不需要验证的动作
		foreach ( Config::get( 'rbac.no_auth' ) as $noAuth ) {
			if ( strtolower( $noAuth ) == strtolower( APP . '.' . MODULE . '.' . CONTROLLER . '.' . ACTION ) ) {
				return true;
			}
		}

		if ( ! $this->isLogin() ) {
			return false;
		}

		//检测超级管理员
		if ( $this->isSuperUser() ) {
			return true;
		}

		//没有权限节点或时时验证时
		//都要从数据库中取权限节点信息
		if ( ! Session::get( '__RBAC__' ) || Config::get( 'rbac.type' ) == 1 ) {
			$node = $this->getUserNode( $_SESSION[ $this->auth_key ] );
			Session::set( '__RBAC__', $node );
		}

		//权限检查
		foreach ( Session::get( '__RBAC__' ) as $app => $a ) {
			if ( strtolower( APP ) == strtolower( $app ) ) {
				$node = Session::get( '__RBAC__.' . strtolower( APP ) . '._NODE_' );
				foreach ( $node as $module => $a ) {
					if ( strtolower( $module ) == strtolower( MODULE ) ) {
						foreach ( $a['_NODE_'] as $controller => $m ) {
							if ( strtolower( $controller ) == strtolower( CONTROLLER ) ) {
								if ( isset( $a['_NODE_'][ strtolower( CONTROLLER ) ]['_NODE_'][ strtolower( ACTION ) ] ) ) {
									return true;
								}
							}
						}
					}
				}
			}
		}

		return false;
	}

	/**
	 * 超级管理员检测
	 *
	 * @return boolean [description]
	 */
	public function isSuperUser() {
		if ( ! $this->isLogin() ) {
			return false;
		}
		if ( Session::get( '__SUPER_USER__' ) ) {
			return true;
		}
		$username = Db::table( Config::get( 'rbac.user_table' ) )
		              ->where( $this->auth_key, Session::get( $this->auth_key ) )
		              ->pluck( 'username' );
		if ( $username == Config::get( 'rbac.super_user' ) ) {
			Session::set( '__SUPER_USER__', true );

			return true;
		}
	}

	/**
	 * 格式化节点为层级结构
	 *
	 * @param $data
	 *
	 * @return array
	 */
	private function formatNode( $data ) {
		$node = [ ];
		foreach ( $data as $d ) {
			if ( $d['level'] == 1 ) {
				$node[ strtolower( $d['name'] ) ] = $d;
				foreach ( $data as $m ) {
					if ( $m['pid'] == $d['id'] ) {
						$node[ strtolower( $d['name'] ) ]['_NODE_'][ strtolower( $m['name'] ) ] = $m;
						foreach ( $data as $n ) {
							if ( $n['pid'] == $m['id'] ) {
								$node[ strtolower( $d['name'] ) ]['_NODE_'][ strtolower( $m['name'] ) ]['_NODE_'][ strtolower( $n['name'] ) ] = $n;
								foreach ( $data as $a ) {
									if ( $a['pid'] == $n['id'] ) {
										$node[ strtolower( $d['name'] ) ]['_NODE_'][ strtolower( $m['name'] ) ]['_NODE_'][ strtolower( $n['name'] ) ]['_NODE_'][ strtolower( $a['name'] ) ] = strtolower( $a['name'] );
									}
								}
							}
						}
					}
				}
			}
		}

		return $node;
	}
}
