package ims

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/alertmanager/types"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Notifier struct {
	conf   *config.IMSConfig
	tmpl   *template.Template
	logger log.Logger
	client *http.Client
}

type imsMessage struct {
	UserAuthKey   string `json:"user_auth_key"`
	AlertTitle    string `json:"alert_title"`
	SubsystemId   int    `json:"subsystem_id"`
	AlertLevel    int    `json:"alert_level,omitempty"`
	AlertObj      string `json:"alert_obj,omitempty"`
	AlertInfo     string `json:"alert_info,omitempty"`
	AlertWay      string `json:"alert_way,omitempty"`
	AlertIp       string `json:"alert_ip,omitempty"`
	AlertReceiver string `json:"alert_receiver,omitempty"`
	RemarkInfo    string `json:"remark_info,omitempty"`
	UseUmgPolicy  int    `json:"use_umg_policy,omitempty"`
	CITypeName    string `json:"ci_type_name,omitempty"`
	CIName        string `json:"ci_name,omitempty"`
}

type imsResponse struct {
	ResultCode int    `json:"resultCode"`
	ResultMsg  string `json:"resultMsg"`
}

// New returns a new IMS notifier.
func New(c *config.IMSConfig, t *template.Template, l log.Logger) (*Notifier, error) {
	client, err := commoncfg.NewClientFromConfig(*c.HTTPConfig, "ims", false)
	if err != nil {
		return nil, err
	}

	return &Notifier{conf: c, tmpl: t, logger: l, client: client}, nil
}

// Notify implements the Notifier interface.
func (n *Notifier) Notify(ctx context.Context, as ...*types.Alert) (bool, error) {
	// check the
	//filteredAlerts := make([]*types.Alert, 0)
	//for _, a := range as {
	//	if err := n.validateAlert(a); err != nil {
	//		level.Debug(n.logger).Log("warn", err, a)
	//		continue
	//	}
	//	ip := n.getInstanceIp(a)
	//	if ip == "" {
	//		level.Debug(n.logger).Log("warn", fmt.Sprintf("cannot get ip from this alert: %v, skip", a))
	//		continue
	//	}
	//	a.Labels[model.LabelName("instance_ip")] = model.LabelValue(ip)
	//	filteredAlerts = append(filteredAlerts, a)
	//}
	key, err := notify.ExtractGroupKey(ctx)
	if err != nil {
		return false, err
	}
	postAlertUrl := n.conf.APIUrl.Copy()
	for _, a := range as {
		data := notify.GetTemplateData(ctx, n.tmpl, []*types.Alert{a}, n.logger)
		if err = n.validateAlert(a); err != nil {
			level.Debug(n.logger).Log("warn", err, a)
			continue
		}
		ip := n.getInstanceIp(a)
		if ip == "" {
			level.Debug(n.logger).Log("warn", fmt.Sprintf("cannot get ip from this alert: %v, skip", a))
			continue
		}
		subsystemID := 0
		subsystemID, err = n.getSubsystemID(a)
		if err != nil {
			level.Debug(n.logger).Log("warn", err)
			continue
		}
		tmpl := notify.TmplText(n.tmpl, data, &err)
		if err != nil {
			return false, err
		}

		msg := imsMessage{
			UserAuthKey:   tmpl(n.conf.UserAuthKey),
			AlertLevel:    n.getLevel(a),
			AlertWay:      tmpl(n.conf.AlertWay),
			AlertTitle:    tmpl(n.getTitle(a)),
			AlertObj:      tmpl(n.getAlertObj(a)),
			AlertIp:       ip,
			SubsystemId:   subsystemID,
			AlertInfo:     tmpl(n.conf.Message),
			AlertReceiver: tmpl(strings.Join(n.conf.Receivers, ",")),
			RemarkInfo:    string(a.Labels[model.LabelName("remark_info")]),
			UseUmgPolicy:  n.conf.UseUmgPolicy,
			CITypeName:    tmpl(n.getCIType(a)),
			CIName:        tmpl(n.getCIName(a)),
		}
		var buf bytes.Buffer
		if err = json.NewEncoder(&buf).Encode(msg); err != nil {
			return false, err
		}

		retryTimes := 0
		for ; retryTimes < 3; retryTimes++ {
			if retryTimes != 0 {
				time.Sleep(time.Millisecond * 100)
			}

			resp := &http.Response{}
			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				resp, err = notify.PostJSON(ctx, n.client, postAlertUrl.String(), &buf)
				if err != nil {
					return
				}
				defer notify.Drain(resp)
				defer wg.Done()

				if resp.StatusCode != 200 {
					err = fmt.Errorf("unexpected status code %v", resp.StatusCode)
					return
				}
				body := make([]byte, 0)
				body, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					return
				}
				level.Debug(n.logger).Log("response", string(body), "incident", key)

				var imsResp imsResponse
				if err = json.Unmarshal(body, &imsResp); err != nil {
					return
				}

				if imsResp.ResultCode == 0 {
					return
				} else {
					err = fmt.Errorf("ims response code != 0, message=%s", imsResp.ResultMsg)
				}
			}()
			wg.Wait()
		}
		if retryTimes == 3 {
			level.Warn(n.logger).Log("warn", "send alert to ims failed", err, "alert: ", a)
		}
	}
	return false, nil
}

func (n *Notifier) getSubsystemID(a *types.Alert) (int, error) {
	if a.Labels == nil {
		return 0, fmt.Errorf("no lebal exists")
	}
	if ss, ok := a.Labels[model.LabelName("subsystem")]; ok {
		if ssi, err := strconv.Atoi(string(ss)); err == nil {
			if ssi < 1000 {
				return 0, fmt.Errorf("invalid subsystem, subsystem id must grate than 1000")
			}
			return ssi, nil
		}
		// todo: get subsystem id via RM
	}
	return 0, fmt.Errorf("'subsystem' label has not be set")
}

func (n *Notifier) getTitle(a *types.Alert) string {
	return n.getLabelValue(a, "title", "alertname")
}

func (n *Notifier) getLevel(a *types.Alert) int {
	ls := n.getLabelValue(a, "alert_level")
	l, err := strconv.Atoi(ls)
	if err != nil {
		return 5
	}
	return l
}

func (n *Notifier) getAlertObj(a *types.Alert) string {
	return n.getAnnotationValue(a, "alert_obj")
}

var labelToGetCIType = model.LabelName("label_to_get_ci_type")
var defaultCITypeLabels = []model.LabelName{"ci_type"}

func (n *Notifier) getCIType(a *types.Alert) string {
	return n.getLabelValue(a, labelToGetCIType, defaultCITypeLabels...)
}

var labelToGetCIName = model.LabelName("label_to_get_ci_name")
var defaultCINameLabels = []model.LabelName{"ci_name"}

func (n *Notifier) getCIName(a *types.Alert) string {
	return n.getLabelValue(a, labelToGetCIName, defaultCINameLabels...)
}

var labelToGetIP = model.LabelName("label_to_get_ip")
var defaultIPLabels = []model.LabelName{"instance_ip", "ip_address", "ip", "pod_ip", "ip_addr", "app_ip"}

func (n *Notifier) getInstanceIp(a *types.Alert) string {
	return n.getLabelValue(a, labelToGetIP, defaultIPLabels...)
}

func (n *Notifier) getLabelValue(a *types.Alert, label model.LabelName, defaultLabels ...model.LabelName) string {
	if a.Labels == nil {
		return ""
	}
	if l, ok := a.Labels[label]; ok {
		return string(a.Labels[model.LabelName(l)])
	} else {
		for _, l := range defaultLabels {
			if lv, o := a.Labels[l]; o {
				return string(lv)
			}
		}
	}
	return ""
}

func (n *Notifier) getAnnotationValue(a *types.Alert, label model.LabelName, defaultLabels ...model.LabelName) string {
	if a.Annotations == nil {
		return ""
	}
	if l, ok := a.Annotations[label]; ok {
		return string(a.Annotations[model.LabelName(l)])
	} else {
		for _, l := range defaultLabels {
			if lv, o := a.Annotations[l]; o {
				return string(lv)
			}
		}
	}
	return ""
}

func (n *Notifier) validateAlert(a *types.Alert) error {
	if a.Labels == nil {
		return fmt.Errorf("no label set")
	}
	if a.Annotations == nil {
		return fmt.Errorf("no annotation set")
	}

	if _, ok := a.Labels[model.LabelName("subsystem")]; !ok {
		return fmt.Errorf("no subsystem label exists")
	}

	if _, ok := a.Annotations[model.LabelName("value")]; !ok {
		return fmt.Errorf("no value annotation exists")
	}
	return nil
}
