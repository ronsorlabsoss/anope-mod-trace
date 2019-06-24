/* TRACE and ALERT implementation for OperServ
 *
 * (C) 2019 Ronsor Labs.
 * This is open-source software from Ronsor Labs.
 * All Ronsor Labs code is provided under the MIT license.
 * However, Anope is still licensed under the GPL.
 *
 * https://github.com/RonsorLabsOSS/anope-mod-trace
 */

#include "module.h"
#include "os_trace/trace.h"

struct TraceData : Serializable
{
	static TraceData *me;
	std::vector<Trace> traces;

	TraceData() : Serializable("Traces")
	{
		me = this;
	}

	void Serialize(Serialize::Data &data) const anope_override
	{
		for (size_t i = 0; i < traces.size(); ++i) {
			if (i > 0)
				data["alerts"] << ",";
			Anope::string ser;
			traces[i].Serialize(ser);
			data["alerts"] << ser;
		}
	}

	static Serializable* Unserialize(Serializable *obj, Serialize::Data &data)
	{
		Anope::string strTraces;
		data["alerts"] >> strTraces;
		std::vector<Anope::string> serTraces;
		sepstream(strTraces, '^').GetTokens(serTraces);
		for (std::vector<Anope::string>::iterator it = serTraces.begin(); it != serTraces.end(); ++it) {
			Trace t(*it);
			me->traces.push_back(t);
		}
		return me;
	}
};

TraceData *TraceData::me;

/**
 * Count servers connected to server s
 * @param s The server to start counting from
 * @return Amount of servers connected to server s
 **/

class CommandOSTrace : public Command
{
 private:
	Module *mod;
 public:
	CommandOSTrace(Module *creator) : Command(creator, "operserv/trace", 3, 32), mod(creator)
	{
		this->SetDesc(_("Perform actions on users matching criteria"));
		this->SetSyntax("\037action\037 \037criteria\037 \037value\037 [\037option\037 \037value\037 | \037criteria\037 \037value\037]... [REASON \037value\037]");
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) anope_override
	{
		try {
			Trace t(params);
			int n = t.Exec(&source);
			source.Reply(_("Performed actions on \002%d\002 user(s)"), n);
		} catch (const ModuleException &exc) {
			source.Reply("Error: %s", exc.GetReason().c_str());
		}
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) anope_override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("TRACE is a powerful command for performing actions on users based on\n"
				"specific criteria.\n"
				"\n"
				"Criteria:\n"
				"  \002MASK \037hostmask\037\002 - Match based on user's hostmask\n"
				"  \002JOINED \037#channel\037\002 - Match users who have joined the specified channel\n"
				"  \002SERVER \037*.server\037\002 - Match users on servers whose names match the specified pattern\n"
				"  \002REALNAME \037Realname*Pattern\037\002 - Match users whose realnames match the specified pattern\n"
				"  \002CERTFP \037ABCDEF...\037\002 - Match the user whose certificate fingerprint matches the one specified\n"
				"  \002TAGGED \037tag\037\002 - Match users tagged with the specified tag\n"
				"  \002ACCOUNT \037username\037\002 - Match users logged into the account specified\n"
				"Actions:\n"
				"  \002NOP\002 - Do nothing, successfully\n"
				"  \002ECHO\002 - Display matched users' hostmasks\n"
				"  \002KILL\002 - KILL matched users\n"
				"  \002SAJOIN\002 - Join matched users to \002TARGET\002\n"
				"  \002SAPART\002 - Part matched users from \002TARGET\002\n"
				"  \002PRIVMSG\002 - Send a message to matched users (\002REASON\002)\n"
				"  \002AKILL\002 - Add an AKILL for matched users\n"
				"  \002TAG\002 - Tag user with \002VALUE\002 for future reference\n"
				"Options:\n"
				"  \002VALUE \037word\037\002 - Specify value to tag user with\n"
				"  \002EXPIRY \0376y5m4w3d2h1m\037\002 - Specify expiry for AKILL actions\n"
				"  \002TARGET \037#channel\037\002 - Target channel; used in some actions\n"
				"  \002REASON \037text here\037\002 - Specify the reason text\n"
				"  \002DISASM 1\002 - Disassemble the TRACE's bytecode; only useful for debugging\n"));
		return true;
	}
};

class OSTrace : public Module
{
	CommandOSTrace commandostrace;
	Serialize::Type trace_type;
	TraceData trace_saver;

 public:
	OSTrace(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, VENDOR),
		commandostrace(this), trace_type("Traces", TraceData::Unserialize)
	{

	}

	void OnUserConnect(User *u, bool &exempt) anope_override
	{
//			trace_saver.QueueUpdate();
	}
};

MODULE_INIT(OSTrace)
