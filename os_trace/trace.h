#include <module.h>
#include <algorithm>

struct TraceAction;
struct TraceCriteria;

static ServiceReference<XLineManager> akills("XLineManager", "xlinemanager/sgline");

static inline Anope::string DUP_STR(const Anope::string &s) {
	return Anope::string(s.c_str());
}

static inline bool EvalExpr(const Anope::string &expr, int number) {
	if (expr.empty())
		return false;
	if (expr.find("<") == 0)
		return number < atoi(expr.c_str() + 1);
	if (expr.find("<=") == 0)
		return number <= atoi(expr.c_str() + 2);
	if (expr.find(">") == 0)
		return number > atoi(expr.c_str() + 1);
	if (expr.find(">=") == 0)
		return number >= atoi(expr.c_str() + 2);
	if (expr.find("<>") == 0)
		return number != atoi(expr.c_str() + 2);
	if (expr.find("=") == 0)
		return number == atoi(expr.c_str() + 1);
	return atoi(expr.c_str()) == number;
}

// FIXME doesn't work right with IRCds that don't use UIDs (ngircd, bahamut)
static std::map<Anope::string, Anope::string> userTags;

#define HAS_CRITERIA(x) (criteria.find(x) != criteria.end())

class Trace {
	bool alreadyDumped;
public:
	std::map<Anope::string, Anope::string> criteria;
	Anope::string action;

	Trace(Anope::string &strExpr) { Unserialize(strExpr); }
	Trace(const std::vector<Anope::string> &expr) { Unserialize(expr); }

	void Unserialize(Anope::string strExpr) {
		std::vector<Anope::string> expr;
		spacesepstream sep(strExpr);
		sep.GetTokens(expr);
		Unserialize(expr);
	}

	void Unserialize(const std::vector<Anope::string> &expr, bool append = false) {
		if (!HAS_CRITERIA("REASON")) criteria["REASON"] = "No reason specified";
		if (expr.size() < (append ? 2 : 3))
			throw ModuleException("TRACE database is corrupt: wrong number of elements in expression (1 or 2), expected at least 3");
		if (!append) {
			action = Trace::Canonicalize(expr[0].upper(), "action");
			if (action.empty()) throw ModuleException("Unknown action: " + expr[0]);
		}
		size_t i; for (i = (append ? 0 : 1); i < expr.size() && (i + 1) < expr.size(); i += 2) {
			Anope::string k(expr[i]);
			k = Trace::Canonicalize(k.upper(), "criteria");
			if (k.empty()) throw ModuleException("Unknown criteria: " + expr[i]);
			criteria[k] = expr[i + 1];
			if (k == "REASON") { // Special case
				for (i = i + 2; i < expr.size(); i++) {
					criteria[k].append(" " + expr[i]);
				}
				break;
			}
		}
		if (i < expr.size())
			throw ModuleException("Unknown criteria: " + expr[i]);
	}

	void Serialize(Anope::string &out) const {
		out.append(action);
		for (std::map<Anope::string, Anope::string>::const_iterator it = criteria.begin(); it != criteria.end(); ++it) {
			if (it->first == "REASON") continue;
			out.append(" ");
			out.append(it->first);
			out.append(" ");
			out.append(it->second);
		}
		if (HAS_CRITERIA("REASON")) { // special case
			out.append(" REASON ");
			out.append((criteria.find("REASON"))->second); // C++ qualifiers rear their ugly head
		}
	}

	static Anope::string Canonicalize(Anope::string in, Anope::string type = "criteria" /* or action */) {
		const char** canonical;
		const char* canon_criteria[] = {"DISASM", "MASK", "REALNAME", "SERVER", "JOINED", "CERTFP", "TARGET", "EXPIRY", "REASON", "VALUE", "TAGGED", "ACCOUNT", "ON", "REGEX", "SESSIONS", NULL};
		const char* canon_action[] = {"COUNT", "AKILL", "KILL", "ECHO", "NOP", "SAJOIN", "SAPART", "PRIVMSG", "TAG", NULL};
		int matches = 0; Anope::string ret;
		if (type == "action") { // Forbidden by ISO C++98, but I don't care
			canonical = canon_action;
		} else if (type == "criteria") {
			canonical = canon_criteria;
		}
		for (const char**s = canonical; *s; s++) {
			if (Anope::string(*s).find(in.upper()) == 0) {
				matches++;
				ret = Anope::string(*s);
			}
		}
		if (matches == 1)
			return ret;
		else
			return "";
	}

	void Validate() { // Throws a ModuleException if something's wrong with the trace
		if (Canonicalize(action, "action").empty())
			throw ModuleException("Invalid action specified: " + action);
		for (std::map<Anope::string, Anope::string>::const_iterator it = criteria.begin(); it != criteria.end(); ++it) {
			if (Canonicalize(it->first, "criteria").empty())
				throw ModuleException("Invalid criteria specified: " + it->first);
			if (it->first == "DISASM" && it->second != "1")
				throw ModuleException("DISASM option only supports '1' as a parameter (enabled)");
			if (it->first == "MASK" && !Anope::Match(it->second, "*!*@*"))
				throw ModuleException("Bad hostmask specified for MASK: " + it->second);
			if ((it->first == "TARGET" || it->first == "JOINED") && it->second.c_str()[0] != '#')
				throw ModuleException("Bad " + it->first + " channel: " + it->second);
		}
		// If we got here, all is ok!
	}

	int Exec(CommandSource *source = NULL) { // Execute trace
		int total = 0;
		for (Anope::hash_map<User*>::const_iterator it = UserListByUID.begin(); it != UserListByUID.end(); ++it) {
			User* user = it->second;
			if (ApplyTo(source, user)) total++;
		}
		return total;
	}

	double CalcEffects() { // Calculate the (rough) percentage of users a trace is likely to affect
		return 0; // TODO
	}

	bool ApplyTo(CommandSource *source, User* user, Anope::string event = "", bool force = false) {
		if (user->server == Me) return false;
		MessageSource* actionSource = source ? (MessageSource*)*source->service : (MessageSource*)Config->GetClient("OperServ");
		if (!actionSource)
			throw ModuleException("Can't determine source user for TRACE actions");
		Anope::string dump;
		this->Serialize(dump);
		if (HAS_CRITERIA("DISASM") && source && !alreadyDumped) {
			source->Reply(_("Disassembly for TRACE: %d bytes"), dump.length());
			int i = 1;
			for (std::map<Anope::string, Anope::string>::const_iterator it = criteria.begin(); it != criteria.end(); ++it) {
				if (it->first == "DISASM")
					source->Reply("%d | ;TRACE compiler options: DISASM", i);
				else
					source->Reply("%d | ASSERT %s, \"%s\"", i, it->first.c_str(), it->second.c_str());
				i++;
			}
			source->Reply("%d | %s ;ACTION", i, action.c_str());
			source->Reply(_("End of source"));
			alreadyDumped = true;
		}
		if (HAS_CRITERIA("SESSIONS") && !force &&
			!EvalExpr(criteria["SESSIONS"], numSess[user->host.lower()])) return false;
		if (HAS_CRITERIA("ON") && !force && DUP_STR(event).upper() != criteria["ON"] && event != "") {
			return false;
		}
		if (HAS_CRITERIA("MASK") && !force &&
			!Anope::Match(user->GetMask(), criteria["MASK"], false, HAS_CRITERIA("REGEX"))) return false;
		if (HAS_CRITERIA("REALNAME") && !force &&
			!Anope::Match(user->realname, criteria["REALNAME"], false, HAS_CRITERIA("REGEX"))) return false;
		if (HAS_CRITERIA("CERTFP") && !force &&
			DUP_STR(criteria["CERTFP"]).upper() != DUP_STR(user->fingerprint).upper())
				return false;
		if (HAS_CRITERIA("JOINED") && !force) {
			Channel *chan = Channel::Find(criteria["JOINED"]);
			if (!chan) return false;
			if (!chan->FindUser(user)) return false;
		}
		if (HAS_CRITERIA("SERVER") && !force &&
			!Anope::Match(user->server->GetName(), criteria["SERVER"]), false, HAS_CRITERIA("REGEX")) return false;
		if (HAS_CRITERIA("ACCOUNT") && !force &&
			user->Account() && !Anope::Match(user->Account()->display, criteria["ACCOUNT"], false, HAS_CRITERIA("REGEX"))) return false;
		if (HAS_CRITERIA("TAGGED") && !force &&
			(userTags.find(user->GetUID()) == userTags.end() || userTags[user->GetUID()] != criteria["TAGGED"])) return false;

		if (source || HAS_CRITERIA("DISASM")) Log() << "os_trace: performing action " << action << " on user " << user->GetMask() << ".";
		if (action == "KILL" && !user->IsProtected())
			user->Kill(Me, criteria["REASON"]);
		else if (action == "AKILL" && !user->IsProtected()) {
			Anope::string expiry = HAS_CRITERIA("EXPIRY") ? criteria["EXPIRY"] : "";
			time_t expires = HAS_CRITERIA("EXPIRY") ? Anope::DoTime(criteria["EXPIRY"]) : Config->GetModule("operserv")->Get<time_t>("autokillexpiry", "30d");
			if (!expiry.empty() && isdigit(expiry[expiry.length() - 1])) expires *= 86400;
			if (expires && expires < 60) {
				if (source) source->Reply(BAD_EXPIRY_TIME);
				else Log() << "TRACE: " << BAD_EXPIRY_TIME << " for " << dump << ".";
				return false;
			}
			expires += Anope::CurTime;
			XLine *x = new XLine("*@" + user->host, source ? source->GetNick() : "OS_TRACE", expires, criteria["REASON"], XLineManager::GenerateUID());
			akills->AddXLine(x);
			akills->OnMatch(user, x);
		} else if (action == "SAJOIN" && HAS_CRITERIA("TARGET"))
			if (!IRCD->CanSVSJoin) {
				Log() << "Not supported by IRCd";
				return false;
			} else
				IRCD->SendSVSJoin(*actionSource, user, criteria["TARGET"], "");
		else if (action == "SAPART" && HAS_CRITERIA("TARGET"))
			if (!IRCD->CanSVSJoin) {
				Log() << "Not supported by IRCd";
				return false;
			} else
				IRCD->SendSVSPart(*actionSource, user, criteria["TARGET"], criteria["REASON"]);
		else if (action == "PRIVMSG") // don't mind the cast, this is guaranteed to be a BotInfo
			user->SendMessage((BotInfo*)actionSource, "%s", criteria["REASON"].c_str());
		else if (action == "ECHO")
			if (source)
				source->Reply(_("Matched %s | %s | tag: %s"), user->GetMask().c_str(), user->realname.c_str(), userTags.find(user->GetUID()) != userTags.end() ? userTags[user->GetUID()].c_str() : "<none>");
			else
				Log() << "User " << user->GetMask() << " was matched by TRACE " << dump << ".";
		else if (action == "TAG" && HAS_CRITERIA("VALUE"))
			userTags[user->GetUID()] = criteria["VALUE"];
		else if (action == "NOP" || action == "COUNT") {} // No-op (technically just count)
		else
			throw ModuleException("Invalid ACTION " + action);
		return true;
	}
};

