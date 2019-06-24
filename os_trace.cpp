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

static std::vector<Trace> allTraces;

struct TraceData : Serializable
{
	static TraceData *me;

	TraceData() : Serializable("Traces")
	{
		me = this;
	}

	void Serialize(Serialize::Data &data) const anope_override
	{
		for (size_t i = 0; i < allTraces.size(); ++i) {
			if (i > 0)
				data["alerts"] << ",";
			Anope::string ser;
			allTraces[i].Serialize(ser);
			data["alerts"] << ser;
		}
	}

	static Serializable* Unserialize(Serializable *obj, Serialize::Data &data)
	{
		Anope::string strTraces;
		data["alerts"] >> strTraces;
		std::vector<Anope::string> serTraces;
		sepstream(strTraces, '^').GetTokens(serTraces);
		allTraces.clear();
		for (std::vector<Anope::string>::iterator it = serTraces.begin(); it != serTraces.end(); ++it) {
			Trace t(*it);
			allTraces.push_back(t);
		}
		return me;
	}

	void Exec() {
		for (std::vector<Trace>::iterator it = allTraces.begin(); it != allTraces.end(); ++it) {
			try {
				(*it).Exec();
			} catch (const ModuleException &exc) {
				Log() << "TRACE failed: " + exc.GetReason();
			}
		}
	}

	void ApplyTo(User *u, Anope::string event = "") {
		for (std::vector<Trace>::iterator it = allTraces.begin(); it != allTraces.end(); ++it) {
			try {
				(*it).ApplyTo(NULL, u, event);
			} catch (const ModuleException &exc) {
				Log() << "TRACE failed: " + exc.GetReason();
			}
		}
	}
};

TraceData *TraceData::me;

class CommandOSAlert : public Command
{
 private:
	Module *mod;
 public:
	CommandOSAlert(Module *creator) : Command(creator, "operserv/alert", 1, 33), mod(creator) {
		this->SetDesc(_("Automatically perform actions on users matching criteria"));
		this->SetSyntax("ADD \037action\037 \037criteria\037 \037value\037 [\037option\037 \037value\037 | \037criteria\037 \037value\037]... [REASON \037value\037]");
		this->SetSyntax("APPEND \037id\037 \037criteria\037 \037value\037 [\037option\037 \037value\037 | \037criteria\037 \037value\037]... [REASON \037value\037]");
		this->SetSyntax("EXEC \037id\037");
		this->SetSyntax("DEL \037id\037");
		this->SetSyntax("LIST");
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) anope_override {
		Anope::string subCmd = params[0];
		subCmd = subCmd.upper();
		do { // Allow break to work
			if (subCmd == "ADD") {
				if (params.size() < 4) {
					this->SendSyntax(source);
					break;
				}
				std::vector<Anope::string> traceParams(params.begin() + 1, params.end());
				try {
					Trace t(traceParams);
					t.Validate();
					allTraces.push_back(t);
					size_t newID = allTraces.size();
					source.Reply(_("TRACE ID: \002%d\002."), newID);
				} catch (const ModuleException &exc) {
					source.Reply("Error: %s", exc.GetReason().c_str());
				}
			}
			else if (subCmd == "LIST") {
				std::vector<Trace> &traces = allTraces;
				size_t i; for (i = 0; i < traces.size(); i++) {
					Anope::string dump;
					traces[i].Serialize(dump);
					source.Reply("%d: %s", i + 1, dump.c_str());
				}
				source.Reply(_("Total %d TRACEs."), i);
			}
			else if (subCmd == "EXEC") {
				if (params.size() != 2) {
					this->SendSyntax(source);
					break;
				}
				int n = std::atoi(params[1].c_str());
				if (n < 1 || (size_t)n > allTraces.size()) {
					source.Reply(_("The TRACE %d doesn't exist."), n);
					break;
				}
				n = n - 1;
				try {
					allTraces[n].Exec();
				} catch (const ModuleException &exc) {
					source.Reply("Error: %s", exc.GetReason().c_str());
				}
			}
			else if (subCmd == "APPEND") {
				if (params.size() < 4) {
					this->SendSyntax(source);
					break;
				}
				std::vector<Anope::string> traceParams(params.begin() + 2, params.end());
				int n = std::atoi(params[1].c_str());
				if (n < 1 || (size_t)n > allTraces.size()) {
					source.Reply(_("The TRACE %d doesn't exist."), n);
					break;
				}
				n = n - 1;
				try {
					allTraces[n].Unserialize(traceParams, true);
				} catch (const ModuleException &exc) {
					source.Reply("Error: %s", exc.GetReason().c_str());
				}
				source.Reply(_("Appended to TRACE %d"), n + 1);
			}
			else if (subCmd == "DEL") {
				if (params.size() != 2) {
					this->SendSyntax(source);
					break;
				}
				int n = std::atoi(params[1].c_str());
				if (n < 1 || (size_t)n > allTraces.size()) {
					source.Reply(_("The TRACE %d doesn't exist."), n);
					break;
				}
				n = n - 1;
				allTraces.erase(allTraces.begin() + n);
				source.Reply(_("Deleted TRACE %d."), n + 1);
			}
			else this->SendSyntax(source);
		} while(0);
		TraceData::me->QueueUpdate();
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) anope_override {
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("ALERT is a powerful command that allows you to automatically apply actions to users\n"
				"using queries called TRACEs.\n"
				"\n"
				"To see the syntax for these queries, view the help for the TRACE command: \002HELP TRACE\002.\n"
				"\n"
				"\002ALERT APPEND\002 allows you to add more criteria to an existing TRACE."));
		return true;
	}
};

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
			t.Validate();
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
				"  \002ON [\037CONNECT\037 | \037JOIN\037 | \037IDENTIFY\037 | \037NICK\037]\002 - Occur because of a specific event; only useful with \002ALERT\002\n"
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
	CommandOSAlert commandosalert;
	Serialize::Type trace_type;
	TraceData trace_saver;

 public:
	OSTrace(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, VENDOR),
		commandostrace(this), commandosalert(this), trace_type("Traces", TraceData::Unserialize)
	{

	}

	void OnUserConnect(User *u, bool &exempt) anope_override
	{
		trace_saver.ApplyTo(u, "CONNECT");
	}

	void OnJoinChannel(User *u, Channel *c) anope_override
	{
		trace_saver.ApplyTo(u, "JOIN");
	}
	void OnUserNickChange(User *u, const Anope::string &oldnick)
	{
		trace_saver.ApplyTo(u, "NICK");
	}
	void OnNickIdentify(User *u) {
		trace_saver.ApplyTo(u, "IDENTIFY");
	}
};

MODULE_INIT(OSTrace)
