import datetime

def parse_crl_date(date_string):
    log = logging.getLogger("SmimeX509Validation.parse_crl_date")
    log.debug("parse_crl_date.input=%s" % (date_string))
    splitdata = date_string.split(' ')
    date_list = []
    for item in splitdata:
        stripeditem = item.strip()
        if len(stripeditem) > 0:
            date_list.append(stripeditem)
    months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
    month_no = months.index(str(date_list[0])) +1
    timelist = date_list[2].split(':')
    output = datetime.datetime(int(date_list[3]),month_no,int(date_list[1]),
        int(timelist[0]),int(timelist[1]),int(timelist[2]))
    log.debug("parse_crl_date.output=%s" % (output.isoformat()))
    return output
