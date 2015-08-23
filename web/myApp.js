angular.module('myApp', []).controller(
		'gwCtrl', function($scope, $http, $interval) {
	$scope.gateways = [];
	$scope.tick = function() {
		$http.get('/gateways.json').success(function(response) {
			$scope.gateways = response;
		});
	};
	$scope.tick();
	$interval($scope.tick, 3000);
});
