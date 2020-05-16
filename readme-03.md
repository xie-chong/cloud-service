# <p align="center">datatables 分页查询</p>

- [1. DataTables官网地址](#1)   
- [2. 项目中的应用](#2)   
  - [2.1 定义table的id](#2.1)   
  - [2.2 定义function](#2.2)   
- [3. 参数说明](#3)   
  - [3.1 serverSide开启服务端分页](#3.1)   
  - [3.2 每页默认条数](#3.2)   
  - [3.3 排序](#3.3)   
  - [3.4 个别列的排序](#3.4)   
  - [3.5 查询接口ajax](#3.5)   
      - [1)	url](#3.5.1)   
      - [2)	type](#3.5.2)   
      - [3)	data](#3.5.3)   
  - [3.6 Datatables数据返回格式](#3.6)   
      - [1)	默认返回数据格式](#3.6.1)   
      - [2)	修改返回数据格式](#3.6.2)   
  - [3.7 数据渲染](#3.7)   
      - [1)	columns](#3.7.1)   
      - [2)	data](#3.7.2)   
      - [3)	render](#3.7.3)   



---

---

---
<h2 id="1">1. DataTables官网地址</h2>

---

中文
http://www.datatables.club/reference/option/
英文
https://www.datatables.net/reference/index

英文网的资料更多些。一些属性用法可以在这里搜索






---
<h2 id="2">2. 项目中的应用</h2>

---

在我们的查询分页页面，基本就用到了datatables组件。如用户查询userList.html，除去引入css和js，我们做下简单的使用介绍。


---
<h3 id="2.1">2.1 定义table的id</h3>

---

```
<table id="dt-table" class="table table-striped table-bordered table-hover" style="width:100%">
	<thead>
		<tr>
		</tr>                       
		<tr>
			<th>username</th>
			<th>昵称</th>
			<th>手机号</th>
			<th>类型</th>
			<th>状态</th>     
			<th>操作</th>
		</tr>
	</thead>
	<tbody>
	</tbody>
</table>
```

---
<h3 id="2.2">2.2 定义function</h3>

---

```
var example;
function init(){
	example = 
		$('#dt-table').DataTable({
			"searching": false,
			"processing": false,
			"serverSide" : true,
			"ordering" :false,
			"language": {
				"url": "../../js/plugin/datatables/Chinese.lang"
			},
			"ajax": {
				"url" : domainName + "/api-u/users",
				"type":"get",
				"data":function(d){
					d.username = $('#username').val();
					d.nickname = $('#nickname').val();
					d.enabled = $("#enabled").val();
					d.type = $("#type").val();
				},
				"dataSrc": function (json) {
					json.recordsTotal=json.total;
					json.recordsFiltered=json.total;
					return json.data;
				},
				"error":function(xhr, textStatus, errorThrown){
					var msg = xhr.responseText;
					console.log(msg);
					if (xhr.status == 400) {
						layer.msg(JSON.parse(msg).message);
					} else if (xhr.status == 401) {
						localStorage.removeItem("token");
						layer.msg("token过期，请重新登录", {shift: -1, time: 1000}, function(){
							location.href = loginPage;
						});
					} else if (xhr.status == 403) {
						layer.msg('未授权');
					} else if (xhr.status == 500) {
						var info = JSON.parse(msg);
						var exception = info.exception;
						var message = info.message;
						layer.msg('系统错误：' + (exception ? exception : message));
					}
				}
			},
			"dom": "<'dt-toolbar'r>t<'dt-toolbar-footer'<'col-sm-10 col-xs-12 hidden-xs'i><'col-xs-12 col-sm-10' p v>>",	
			"columns": [
				{ "data": "username", "defaultContent": ""},
				{ "data": "nickname", "defaultContent": ""},
				{ "data": "phone", "defaultContent": ""},
				{ 
					"data": "type",
					"defaultContent": "",
					"render": function (data, type, row) {
						if(data =="BACKEND"){
							return "后端管理用户";
						}
						return "前端app用户";
					}
				},
				{ 
					"data": "enabled",
					"defaultContent": "",
					"render": function (data, type, row) {
						if(data){
							return "正常";
						}
						return "禁用";
					}
				},
				{ 
					"data": "", 
					"defaultContent": "",
					"render": function (data, type, row) {
						var id = row['id'];
						var href = "updateUser.html?id=" + id;
						var edit = buttonEdit(href, "back:user:update", pers);
						
						//重置密码
						var resetPassword = "";
						if($.inArray("back:user:password", pers) >= 0){
							var btn = $("<button class='layui-btn layui-btn-xs'><i class='layui-icon'>重置密码</i></button>");
							btn.attr("onclick", 'resetPassword(' +id+')');
							resetPassword = btn.prop("outerHTML");
						}
						
						//分配角色
						var setRoles = "";
						if($.inArray("back:user:role:set", pers) >= 0){
							var btn = $("<button class='layui-btn layui-btn-xs'><i class='layui-icon'>分配角色</i></button>");
							btn.attr("onclick", 'setRoles(' +id+')');
							setRoles = btn.prop("outerHTML");
						}
						return edit + resetPassword + setRoles;
					}
				},
			],
		} );
}
```
这里进入页面我们默认执行以下这个方法，就是打开就进行查询数据。   
```
    init();
```

这里是搜索按钮做了一个click绑定。   
```
$("#searchBt").click(function(){
	example.ajax.reload();
});
```


---
<h2 id="3">3. 参数说明</h2>

---
如下所示的一些参数：   
```
var example;
function init(){
	example = 
		$('#dt-table').DataTable({
			"searching": false,
			"processing": false,
			"serverSide" : true,
			"ordering" :false,
			"language": {
				"url": "../../js/plugin/datatables/Chinese.lang"
			},
```

---
<h3 id="3.1">3.1 serverSide开启服务端分页</h3>

---

这个参数为true是开启服务端分页，为true之后，发起请求的话，会带上参数start和length，start是开始位置，从0开始，length是每页数量，默认为10。




---
<h3 id="3.2">3.2 每页默认条数</h3>

---

```
pageLength: 更改初始页面长度（每页的行数）。
```

**描述**   
使用分页时在单个页面上显示的行数。


**默认值：** 10   
**例** 每页显示50条记录：

```
$('#example').dataTable( {<font></font>
  "pageLength": 50<font></font>
} );
```




---
<h3 id="3.3">3.3 排序</h3>

---

```
odering: 数据表中的功能控件排序（排序）功能。
```

**描述**   
启用或禁用列排序-就这么简单！默认情况下，DataTables允许最终用户单击每一列的标题单元格，并根据该列中的数据对表进行排序。可以使用此选项禁用订购数据的功能。


**默认值：** true   
**例** 关闭表格的排序功能

```
$('#example').dataTable( {
  "ordering": false
} );
```



---
<h3 id="3.4">3.4 个别列的排序</h3>

---

```
columns.orderable: 开启/禁用这列是否排序。
```

**描述**   
以通过columns.orderable每个列的选项禁用添加或删除单个列排序的功能。此参数是全局选项-禁用后，DataTables根本不会应用任何排序操作。


**默认值：** true   
**例** 关闭表格的排序功能   
Disable ordering on the first column with columnDefs:   
```
$('#example').dataTable( {
  "columnDefs": [
    { "orderable": false, "targets": 0 }
  ]
} );
```
Disable ordering on the first column with columns:
```
$('#example').dataTable( {
  "columns": [
    { "orderable": false },
    null,
    null,
    null,
    null
  ]
} );
```



---
<h3 id="3.5">3.5 查询接口ajax</h3>

---

```
"ajax": {
	"url" : domainName + "/api-u/users",
	"type":"get",
	"data":function(d){
		d.username = $('#username').val();
		d.nickname = $('#nickname').val();
		d.enabled = $("#enabled").val();
		d.type = $("#type").val();
	},
	"dataSrc": function (json) {
		json.recordsTotal=json.total;
		json.recordsFiltered=json.total;
		return json.data;
	},
	"error":function(xhr, textStatus, errorThrown){
	// ......
```

---
<h4 id="3.5.1">1)	url</h4>

---

这里url就是我们的接口地址

---
<h4 id="3.5.2">2)	type</h4>

---

可以指定我们是get请求，还是post请求
**注意**：
如果列比较多的话，可能会往服务端发送的参数特别多，这时候get请求已经不行了，需要用post请求，后端改为post接口。

---
<h4 id="3.5.3">3)	data</h4>

---

指定查询参数，如
```
"data":function(d){
	d.username = $('#username').val();
	d.nickname = $('#nickname').val();
	d.enabled = $("#enabled").val();
	d.type = $("#type").val();
},
```
如上的例子，在data里这样写，访问接口的时候，会发送参数名为username、nickname、status的参数，这里主要是我们自己做查询的时候的一些搜索条件。





---
<h3 id="3.6">3.6 Datatables数据返回格式</h3>

---

首先ajax返回的数据要是json格式的，最起码要有数据总数量，和数据集合列表。

---
<h4 id="3.6.1">1)	默认返回数据格式</h4>

---

```
{
	"recordFilter":101,
	"data":[],
	"recordsTotal":101
}
```

默认要有这三个字段   
* data是数据集合，
* recordsTotal是用来计算总页数的
* recordsFiltered用来做显示的



---
<h4 id="3.6.2">2)	修改返回数据格式</h4>

---

如果我们没按照datatables默认的数据返回格式返回，如我们返回的是   
```
{
	"total":101,
	"list]
}
```

那么datatables默认是不能解析的，我们可以用参数dataSrc   
```
"ajax": {
	"url" : domainName + "/api-u/users",
	"type":"get",
	"data":function(d){
		d.username = $('#username').val();
		d.nickname = $('#nickname').val();
		d.enabled = $("#enabled").val();
		d.type = $("#type").val();
	},
	"dataSrc": function (json) {
		json.recordsTotal=json.total;
		json.recordsFiltered=json.total;
		return json.data;
	},
```

顾名思义，dataSrc就是数据源，这里的参数json其实datatables就是根据他的数据来渲染表格的，我们将total赋值给recordsTotal和recordsFiltered，然后呢，把数据集合return,datatabls就是根据这个结果来渲染数据。




---
<h3 id="3.7">3.7 数据渲染</h3>

---

---
<h4 id="3.7.1">1)	columns</h4>

---

通过columns字段进行数据渲染，如下   
```
"columns": [
	{ "data": "username", "defaultContent": ""},
	{ "data": "nickname", "defaultContent": ""},
	{ "data": "phone", "defaultContent": ""},
	{
		"data": "type",
		"defaultContent": "",
		"render": function (data, type, row) {
			if(data =="BACKEND"){
				return "后端管理用户";
			}
			return "前端app用户";
		}
	},
	{
		"data": "enabled",
		"defaultContent": "",
		"render": function (data, type, row) {
			if(data){
				return "正常";
			}
			return "禁用";
		}
	},
	{
		"data": "",
		"defaultContent": "",
		"render": function (data, type, row) {
			var id = row['id'];
			var href = "updateUser.html?id=" + id;
			var edit = buttonEdit(href, "back:user:update", pers);
// ......
```

这里columns集合里的元素个数，需要跟如下所示的个数一样，其实就是一个th对应一个{ "data": "username", "defaultContent": ""},这种格式的数据。

```
<table id="dt-table" class="table table-striped table-bordered table-hover" style="width:100%">
	<thead>
		<tr>
		</tr>
		<tr>
			<th>username</th>
			<th>昵称</th>
			<th>手机号</th>
			<th>类型</th>
			<th>状态</th>
			<th>操作</th>
		</tr>
	</thead>
	<tbody>
	</tbody>
</table>
```


---
<h4 id="3.7.2">2)	data</h4>

---

```
"columns": [
	{ "data": "username", "defaultContent": ""},
// ......
```

如上所示，data里的username对应json里的username，这一列将根据json里username的值进行显示。


---
<h4 id="3.7.3">3)	render</h4>

---

```
{
	"data": "",
	"defaultContent": "",
	"render": function (data, type, row) {
		var id = row['id'];
		var href = "updateUser.html?id=" + id;
		var edit = buttonEdit(href, "back:user:update", pers);
// .......
```

如上所示，操作列因为不跟某个字段直接对应， 这里用render进行处理，参数row就是那一行的json数据，你也可以用data指定具体那个数据，如下所示   

```
{
	"data": "enabled",
	"defaultContent": "",
	"render": function (data, type, row) {
	// .......
```

这里写成"data": "enabled"，那么function中的data的值就是json里key为enabled的对应的值。
