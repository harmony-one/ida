set -eu

unset -v libraptorq_root eigen_root
libraptorq_root=/usr/local
eigen_root=/usr/local

unset -v opt

while getopts :R:Q:E: opt
do
	case "${opt}" in
	'?')
		echo "unrecognized option -${OPTARG}" >&2
		exit 64
		;;
	':')
		echo "missing argument for -${OPTARG}" >&2
		exit 64
		;;
	R)
		libraptorq_root="${OPTARG}"
		eigen_root="${OPTARG}"
		;;
	Q)
		libraptorq_root="${OPTARG}"
		;;
	E)
		eigen_root="${OPTARG}"
		;;
	esac
done
shift $((${OPTIND} - 1))

unset -v root
(
	echo "${libraptorq_root}"
	echo "${eigen_root}"
) |
sort -u | (
	while read -r root
	do
		CGO_CPPFLAGS="${CGO_CPPFLAGS+"${CGO_CPPFLAGS} "}-I${root}/include"
		CGO_LDFLAGS="${CGO_LDFLAGS+"${CGO_LDFLAGS} "}-L${root}/lib"
	done
	CGO_CXXFLAGS="${CGO_CXXFLAGS+"${CGO_CXXFLAGS} "}-std=c++11"

	export CGO_CPPFLAGS CGO_CXXFLAGS CGO_LDFLAGS
	printenv | grep CGO
	exec go build "$@"
)
