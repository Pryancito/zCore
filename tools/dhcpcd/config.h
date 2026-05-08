/* linux */

#ifndef CONFIG_H
#define CONFIG_H

#ifndef	SYSCONFDIR
#define	SYSCONFDIR		"/etc"
#define	SBINDIR			"/bin"
#define	LIBDIR			"/lib"
#define	LIBEXECDIR		"/lib/dhcpcd"
#define	DBDIR			"/var/lib/dhcpcd"
#define	RUNDIR			"/var/run/dhcpcd"
#endif
#include		<asm/types.h> /* fix broken headers */
#include		<sys/socket.h> /* fix broken headers */
#include		<linux/rtnetlink.h>
#define	HAVE_NL80211_H
#define	HAVE_IN6_ADDR_GEN_MODE_NONE
#include			"compat/closefrom.h"
#define	IOCTL_REQUEST_TYPE	int
#include			"compat/arc4random.h"
#include			"compat/arc4random_uniform.h"
#define	HAVE_EXPLICIT_BZERO
#define	HAVE_OPEN_MEMSTREAM
#include			"compat/pidfile.h"
#include			"compat/setproctitle.h"
#include			"compat/strtoi.h"
#include			"compat/consttime_memequal.h"
#define	HAVE_REALLOCARRAY
#include			"compat/endian.h"
#include			"compat/crypt/md5.h"
#include			"compat/crypt/sha256.h"
#include			"compat/crypt/hmac.h"

#endif /*CONFIG_H*/
