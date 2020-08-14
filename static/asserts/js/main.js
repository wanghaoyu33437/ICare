//打开同一navtab标签，若相同则刷新
function openMytab(obj)
{
        $(obj).navtab('refresh')
}

function DGAstart(obj) {
    console.log('开始监测UDP 53端口')
    $.ajax({
        url: '/DGAstart',
        datatype: 'json',
        success:function (data) {
            console.log(data)
        }
    })
    openMytab(obj)
}
function DGAstop(obj) {
    console.log('停止监测UDP 53端口')
    $.ajax({
        url: '/DGAstop',
        datatype: 'json',
        success:function (data) {
            console.log(data)
        }
    })
    openMytab(obj)
}
function DGAdel(obj) {
 console.log('删除DNS流量数据')
    $.ajax({
        url: '/DGAdel',
        datatype: 'json',
        success:function (data) {
            console.log(data)
        }
    })
    openMytab(obj)
    }
function URLstart(obj) {
     console.log('开始监测TCP 80端口')
    $.ajax({
        url: '/URLstart',
        datatype: 'json',
        success:function (data) {
            console.log(data)

        }
    })
    openMytab(obj)
}
function URLstop(obj) {
     console.log('停止监测TCP 80端口')
    $.ajax({
        url: '/URLstop',
        datatype: 'json',
        success:function (data) {
            console.log(data)
        }
    })
    openMytab(obj)
}